rule TTP_XOR_WriteProcessMemory_c6b4 {
  strings:
    $key_c6b4 = { 91 c6 [2] a3 e4 [2] a5 d1 [2] 8b d1 [2] b4 cd }

  condition:
    any of them
}