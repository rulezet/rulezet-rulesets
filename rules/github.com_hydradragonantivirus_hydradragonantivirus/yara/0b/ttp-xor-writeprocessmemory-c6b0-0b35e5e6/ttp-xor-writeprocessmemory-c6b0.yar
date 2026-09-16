rule TTP_XOR_WriteProcessMemory_c6b0 {
  strings:
    $key_c6b0 = { 91 c2 [2] a3 e0 [2] a5 d5 [2] 8b d5 [2] b4 c9 }

  condition:
    any of them
}