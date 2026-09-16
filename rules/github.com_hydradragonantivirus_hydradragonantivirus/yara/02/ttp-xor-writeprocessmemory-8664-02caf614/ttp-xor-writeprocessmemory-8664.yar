rule TTP_XOR_WriteProcessMemory_8664 {
  strings:
    $key_8664 = { d1 16 [2] e3 34 [2] e5 01 [2] cb 01 [2] f4 1d }

  condition:
    any of them
}