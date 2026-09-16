rule TTP_XOR_WriteProcessMemory_c0a0 {
  strings:
    $key_c0a0 = { 97 d2 [2] a5 f0 [2] a3 c5 [2] 8d c5 [2] b2 d9 }

  condition:
    any of them
}