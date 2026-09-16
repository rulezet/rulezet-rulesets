rule TTP_XOR_WriteProcessMemory_54a0 {
  strings:
    $key_54a0 = { 03 d2 [2] 31 f0 [2] 37 c5 [2] 19 c5 [2] 26 d9 }

  condition:
    any of them
}