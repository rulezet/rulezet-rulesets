rule TTP_XOR_WriteProcessMemory_8662 {
  strings:
    $key_8662 = { d1 10 [2] e3 32 [2] e5 07 [2] cb 07 [2] f4 1b }

  condition:
    any of them
}