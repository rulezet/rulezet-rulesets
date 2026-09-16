rule TTP_XOR_WriteProcessMemory_8061 {
  strings:
    $key_8061 = { d7 13 [2] e5 31 [2] e3 04 [2] cd 04 [2] f2 18 }

  condition:
    any of them
}