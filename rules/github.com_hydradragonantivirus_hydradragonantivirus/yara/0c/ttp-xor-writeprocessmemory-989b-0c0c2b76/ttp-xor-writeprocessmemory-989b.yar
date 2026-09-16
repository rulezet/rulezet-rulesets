rule TTP_XOR_WriteProcessMemory_989b {
  strings:
    $key_989b = { cf e9 [2] fd cb [2] fb fe [2] d5 fe [2] ea e2 }

  condition:
    any of them
}