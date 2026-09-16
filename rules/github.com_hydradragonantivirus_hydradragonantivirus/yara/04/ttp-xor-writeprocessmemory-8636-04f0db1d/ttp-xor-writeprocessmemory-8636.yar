rule TTP_XOR_WriteProcessMemory_8636 {
  strings:
    $key_8636 = { d1 44 [2] e3 66 [2] e5 53 [2] cb 53 [2] f4 4f }

  condition:
    any of them
}