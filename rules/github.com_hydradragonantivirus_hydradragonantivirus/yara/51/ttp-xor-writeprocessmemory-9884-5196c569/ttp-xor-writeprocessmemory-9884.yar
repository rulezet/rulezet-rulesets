rule TTP_XOR_WriteProcessMemory_9884 {
  strings:
    $key_9884 = { cf f6 [2] fd d4 [2] fb e1 [2] d5 e1 [2] ea fd }

  condition:
    any of them
}