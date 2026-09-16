rule TTP_XOR_WriteProcessMemory_8071 {
  strings:
    $key_8071 = { d7 03 [2] e5 21 [2] e3 14 [2] cd 14 [2] f2 08 }

  condition:
    any of them
}