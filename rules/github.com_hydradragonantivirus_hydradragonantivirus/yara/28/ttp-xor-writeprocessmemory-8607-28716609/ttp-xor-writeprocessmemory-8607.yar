rule TTP_XOR_WriteProcessMemory_8607 {
  strings:
    $key_8607 = { d1 75 [2] e3 57 [2] e5 62 [2] cb 62 [2] f4 7e }

  condition:
    any of them
}