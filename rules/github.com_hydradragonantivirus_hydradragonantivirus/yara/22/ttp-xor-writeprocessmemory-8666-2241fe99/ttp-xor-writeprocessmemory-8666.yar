rule TTP_XOR_WriteProcessMemory_8666 {
  strings:
    $key_8666 = { d1 14 [2] e3 36 [2] e5 03 [2] cb 03 [2] f4 1f }

  condition:
    any of them
}