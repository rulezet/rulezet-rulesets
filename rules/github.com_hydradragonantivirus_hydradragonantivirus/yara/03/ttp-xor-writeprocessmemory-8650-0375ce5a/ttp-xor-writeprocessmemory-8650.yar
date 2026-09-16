rule TTP_XOR_WriteProcessMemory_8650 {
  strings:
    $key_8650 = { d1 22 [2] e3 00 [2] e5 35 [2] cb 35 [2] f4 29 }

  condition:
    any of them
}