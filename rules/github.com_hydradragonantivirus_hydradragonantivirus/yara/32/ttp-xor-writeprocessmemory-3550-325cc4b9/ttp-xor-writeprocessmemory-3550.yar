rule TTP_XOR_WriteProcessMemory_3550 {
  strings:
    $key_3550 = { 62 22 [2] 50 00 [2] 56 35 [2] 78 35 [2] 47 29 }

  condition:
    any of them
}