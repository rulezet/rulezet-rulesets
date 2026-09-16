rule TTP_XOR_WriteProcessMemory_c0d4 {
  strings:
    $key_c0d4 = { 97 a6 [2] a5 84 [2] a3 b1 [2] 8d b1 [2] b2 ad }

  condition:
    any of them
}