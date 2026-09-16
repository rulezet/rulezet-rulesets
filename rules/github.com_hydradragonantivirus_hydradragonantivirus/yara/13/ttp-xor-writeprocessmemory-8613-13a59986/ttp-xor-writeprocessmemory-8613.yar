rule TTP_XOR_WriteProcessMemory_8613 {
  strings:
    $key_8613 = { d1 61 [2] e3 43 [2] e5 76 [2] cb 76 [2] f4 6a }

  condition:
    any of them
}