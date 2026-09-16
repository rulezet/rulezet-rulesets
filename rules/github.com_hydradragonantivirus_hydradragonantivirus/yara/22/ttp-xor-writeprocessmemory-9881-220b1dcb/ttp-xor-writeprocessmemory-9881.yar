rule TTP_XOR_WriteProcessMemory_9881 {
  strings:
    $key_9881 = { cf f3 [2] fd d1 [2] fb e4 [2] d5 e4 [2] ea f8 }

  condition:
    any of them
}