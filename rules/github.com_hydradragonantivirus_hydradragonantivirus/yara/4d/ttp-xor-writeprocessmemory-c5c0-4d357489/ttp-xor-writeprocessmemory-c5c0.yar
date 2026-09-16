rule TTP_XOR_WriteProcessMemory_c5c0 {
  strings:
    $key_c5c0 = { 92 b2 [2] a0 90 [2] a6 a5 [2] 88 a5 [2] b7 b9 }

  condition:
    any of them
}