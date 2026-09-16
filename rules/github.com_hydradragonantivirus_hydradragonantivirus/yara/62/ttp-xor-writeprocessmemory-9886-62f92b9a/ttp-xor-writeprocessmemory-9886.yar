rule TTP_XOR_WriteProcessMemory_9886 {
  strings:
    $key_9886 = { cf f4 [2] fd d6 [2] fb e3 [2] d5 e3 [2] ea ff }

  condition:
    any of them
}