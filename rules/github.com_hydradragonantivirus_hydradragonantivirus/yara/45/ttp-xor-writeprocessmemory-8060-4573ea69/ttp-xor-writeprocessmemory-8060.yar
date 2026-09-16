rule TTP_XOR_WriteProcessMemory_8060 {
  strings:
    $key_8060 = { d7 12 [2] e5 30 [2] e3 05 [2] cd 05 [2] f2 19 }

  condition:
    any of them
}