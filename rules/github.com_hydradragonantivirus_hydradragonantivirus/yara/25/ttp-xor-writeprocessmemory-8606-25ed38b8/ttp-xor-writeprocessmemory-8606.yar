rule TTP_XOR_WriteProcessMemory_8606 {
  strings:
    $key_8606 = { d1 74 [2] e3 56 [2] e5 63 [2] cb 63 [2] f4 7f }

  condition:
    any of them
}