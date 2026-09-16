rule TTP_XOR_WriteProcessMemory_d5b4 {
  strings:
    $key_d5b4 = { 82 c6 [2] b0 e4 [2] b6 d1 [2] 98 d1 [2] a7 cd }

  condition:
    any of them
}