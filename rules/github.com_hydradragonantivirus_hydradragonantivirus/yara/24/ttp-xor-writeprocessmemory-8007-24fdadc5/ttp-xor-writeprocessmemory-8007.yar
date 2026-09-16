rule TTP_XOR_WriteProcessMemory_8007 {
  strings:
    $key_8007 = { d7 75 [2] e5 57 [2] e3 62 [2] cd 62 [2] f2 7e }

  condition:
    any of them
}