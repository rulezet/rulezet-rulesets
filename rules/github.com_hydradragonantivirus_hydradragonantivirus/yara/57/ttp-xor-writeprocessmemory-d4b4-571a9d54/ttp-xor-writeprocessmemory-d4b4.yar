rule TTP_XOR_WriteProcessMemory_d4b4 {
  strings:
    $key_d4b4 = { 83 c6 [2] b1 e4 [2] b7 d1 [2] 99 d1 [2] a6 cd }

  condition:
    any of them
}