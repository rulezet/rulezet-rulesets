rule TTP_XOR_WriteProcessMemory_8136 {
  strings:
    $key_8136 = { d6 44 [2] e4 66 [2] e2 53 [2] cc 53 [2] f3 4f }

  condition:
    any of them
}