rule TTP_XOR_WriteProcessMemory_8766 {
  strings:
    $key_8766 = { d0 14 [2] e2 36 [2] e4 03 [2] ca 03 [2] f5 1f }

  condition:
    any of them
}