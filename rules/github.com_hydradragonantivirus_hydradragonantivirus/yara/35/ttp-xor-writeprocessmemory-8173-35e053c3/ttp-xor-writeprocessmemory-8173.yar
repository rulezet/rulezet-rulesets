rule TTP_XOR_WriteProcessMemory_8173 {
  strings:
    $key_8173 = { d6 01 [2] e4 23 [2] e2 16 [2] cc 16 [2] f3 0a }

  condition:
    any of them
}