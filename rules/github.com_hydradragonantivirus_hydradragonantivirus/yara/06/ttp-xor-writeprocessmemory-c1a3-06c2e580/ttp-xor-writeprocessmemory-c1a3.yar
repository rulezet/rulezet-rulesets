rule TTP_XOR_WriteProcessMemory_c1a3 {
  strings:
    $key_c1a3 = { 96 d1 [2] a4 f3 [2] a2 c6 [2] 8c c6 [2] b3 da }

  condition:
    any of them
}