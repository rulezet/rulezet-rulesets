rule TTP_XOR_WriteProcessMemory_8630 {
  strings:
    $key_8630 = { d1 42 [2] e3 60 [2] e5 55 [2] cb 55 [2] f4 49 }

  condition:
    any of them
}