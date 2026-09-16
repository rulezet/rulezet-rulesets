rule TTP_XOR_WriteProcessMemory_d1a3 {
  strings:
    $key_d1a3 = { 86 d1 [2] b4 f3 [2] b2 c6 [2] 9c c6 [2] a3 da }

  condition:
    any of them
}