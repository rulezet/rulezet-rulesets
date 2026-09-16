rule TTP_XOR_WriteProcessMemory_8166 {
  strings:
    $key_8166 = { d6 14 [2] e4 36 [2] e2 03 [2] cc 03 [2] f3 1f }

  condition:
    any of them
}