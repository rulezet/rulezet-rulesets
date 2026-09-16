rule TTP_XOR_WriteProcessMemory_d6b4 {
  strings:
    $key_d6b4 = { 81 c6 [2] b3 e4 [2] b5 d1 [2] 9b d1 [2] a4 cd }

  condition:
    any of them
}