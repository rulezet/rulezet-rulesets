rule TTP_XOR_WriteProcessMemory_8674 {
  strings:
    $key_8674 = { d1 06 [2] e3 24 [2] e5 11 [2] cb 11 [2] f4 0d }

  condition:
    any of them
}