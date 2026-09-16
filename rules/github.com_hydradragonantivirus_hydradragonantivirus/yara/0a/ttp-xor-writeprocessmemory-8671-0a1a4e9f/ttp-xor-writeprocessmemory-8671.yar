rule TTP_XOR_WriteProcessMemory_8671 {
  strings:
    $key_8671 = { d1 03 [2] e3 21 [2] e5 14 [2] cb 14 [2] f4 08 }

  condition:
    any of them
}