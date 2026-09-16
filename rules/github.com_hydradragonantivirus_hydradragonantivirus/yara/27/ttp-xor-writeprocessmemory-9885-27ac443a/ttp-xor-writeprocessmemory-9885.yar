rule TTP_XOR_WriteProcessMemory_9885 {
  strings:
    $key_9885 = { cf f7 [2] fd d5 [2] fb e0 [2] d5 e0 [2] ea fc }

  condition:
    any of them
}