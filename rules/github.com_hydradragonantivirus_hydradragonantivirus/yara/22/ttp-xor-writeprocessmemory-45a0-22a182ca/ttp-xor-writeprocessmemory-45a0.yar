rule TTP_XOR_WriteProcessMemory_45a0 {
  strings:
    $key_45a0 = { 12 d2 [2] 20 f0 [2] 26 c5 [2] 08 c5 [2] 37 d9 }

  condition:
    any of them
}