rule TTP_XOR_WriteProcessMemory_d7f0 {
  strings:
    $key_d7f0 = { 80 82 [2] b2 a0 [2] b4 95 [2] 9a 95 [2] a5 89 }

  condition:
    any of them
}