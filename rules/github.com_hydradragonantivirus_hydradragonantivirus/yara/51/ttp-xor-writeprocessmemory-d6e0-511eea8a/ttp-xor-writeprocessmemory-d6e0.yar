rule TTP_XOR_WriteProcessMemory_d6e0 {
  strings:
    $key_d6e0 = { 81 92 [2] b3 b0 [2] b5 85 [2] 9b 85 [2] a4 99 }

  condition:
    any of them
}