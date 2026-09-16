rule TTP_XOR_WriteProcessMemory_8672 {
  strings:
    $key_8672 = { d1 00 [2] e3 22 [2] e5 17 [2] cb 17 [2] f4 0b }

  condition:
    any of them
}