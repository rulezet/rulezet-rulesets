rule TTP_XOR_WriteProcessMemory_8176 {
  strings:
    $key_8176 = { d6 04 [2] e4 26 [2] e2 13 [2] cc 13 [2] f3 0f }

  condition:
    any of them
}