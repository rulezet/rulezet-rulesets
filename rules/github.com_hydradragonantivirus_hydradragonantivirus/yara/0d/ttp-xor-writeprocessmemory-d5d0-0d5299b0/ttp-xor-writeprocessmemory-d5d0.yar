rule TTP_XOR_WriteProcessMemory_d5d0 {
  strings:
    $key_d5d0 = { 82 a2 [2] b0 80 [2] b6 b5 [2] 98 b5 [2] a7 a9 }

  condition:
    any of them
}