rule TTP_XOR_WriteProcessMemory_dab4 {
  strings:
    $key_dab4 = { 8d c6 [2] bf e4 [2] b9 d1 [2] 97 d1 [2] a8 cd }

  condition:
    any of them
}