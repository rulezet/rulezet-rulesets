rule TTP_XOR_WriteProcessMemory_22a0 {
  strings:
    $key_22a0 = { 75 d2 [2] 47 f0 [2] 41 c5 [2] 6f c5 [2] 50 d9 }

  condition:
    any of them
}