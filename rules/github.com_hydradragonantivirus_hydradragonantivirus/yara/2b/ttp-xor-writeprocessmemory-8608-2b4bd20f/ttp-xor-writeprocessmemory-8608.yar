rule TTP_XOR_WriteProcessMemory_8608 {
  strings:
    $key_8608 = { d1 7a [2] e3 58 [2] e5 6d [2] cb 6d [2] f4 71 }

  condition:
    any of them
}