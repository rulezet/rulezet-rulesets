rule TTP_XOR_WriteProcessMemory_8655 {
  strings:
    $key_8655 = { d1 27 [2] e3 05 [2] e5 30 [2] cb 30 [2] f4 2c }

  condition:
    any of them
}