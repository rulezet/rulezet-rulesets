rule TTP_XOR_WriteProcessMemory_8620 {
  strings:
    $key_8620 = { d1 52 [2] e3 70 [2] e5 45 [2] cb 45 [2] f4 59 }

  condition:
    any of them
}