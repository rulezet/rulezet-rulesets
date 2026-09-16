rule TTP_XOR_WriteProcessMemory_d4d0 {
  strings:
    $key_d4d0 = { 83 a2 [2] b1 80 [2] b7 b5 [2] 99 b5 [2] a6 a9 }

  condition:
    any of them
}