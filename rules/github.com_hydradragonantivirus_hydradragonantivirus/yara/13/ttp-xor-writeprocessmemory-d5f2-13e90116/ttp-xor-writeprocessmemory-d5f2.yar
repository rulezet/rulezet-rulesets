rule TTP_XOR_WriteProcessMemory_d5f2 {
  strings:
    $key_d5f2 = { 82 80 [2] b0 a2 [2] b6 97 [2] 98 97 [2] a7 8b }

  condition:
    any of them
}