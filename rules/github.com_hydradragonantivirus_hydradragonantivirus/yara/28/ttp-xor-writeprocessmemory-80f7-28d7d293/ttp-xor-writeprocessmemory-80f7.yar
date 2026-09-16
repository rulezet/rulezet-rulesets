rule TTP_XOR_WriteProcessMemory_80f7 {
  strings:
    $key_80f7 = { d7 85 [2] e5 a7 [2] e3 92 [2] cd 92 [2] f2 8e }

  condition:
    any of them
}