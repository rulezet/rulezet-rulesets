rule TTP_XOR_WriteProcessMemory_8673 {
  strings:
    $key_8673 = { d1 01 [2] e3 23 [2] e5 16 [2] cb 16 [2] f4 0a }

  condition:
    any of them
}