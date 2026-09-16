rule TTP_XOR_WriteProcessMemory_8641 {
  strings:
    $key_8641 = { d1 33 [2] e3 11 [2] e5 24 [2] cb 24 [2] f4 38 }

  condition:
    any of them
}