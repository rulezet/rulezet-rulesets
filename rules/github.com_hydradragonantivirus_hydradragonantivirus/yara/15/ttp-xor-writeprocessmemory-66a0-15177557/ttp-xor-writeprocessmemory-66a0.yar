rule TTP_XOR_WriteProcessMemory_66a0 {
  strings:
    $key_66a0 = { 31 d2 [2] 03 f0 [2] 05 c5 [2] 2b c5 [2] 14 d9 }

  condition:
    any of them
}