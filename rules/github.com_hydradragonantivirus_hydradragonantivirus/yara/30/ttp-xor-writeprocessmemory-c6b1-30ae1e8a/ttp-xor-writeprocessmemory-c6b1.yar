rule TTP_XOR_WriteProcessMemory_c6b1 {
  strings:
    $key_c6b1 = { 91 c3 [2] a3 e1 [2] a5 d4 [2] 8b d4 [2] b4 c8 }

  condition:
    any of them
}