rule TTP_XOR_WriteProcessMemory_d7c0 {
  strings:
    $key_d7c0 = { 80 b2 [2] b2 90 [2] b4 a5 [2] 9a a5 [2] a5 b9 }

  condition:
    any of them
}