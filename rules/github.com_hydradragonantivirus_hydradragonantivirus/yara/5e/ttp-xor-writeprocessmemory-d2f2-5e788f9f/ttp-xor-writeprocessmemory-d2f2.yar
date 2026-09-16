rule TTP_XOR_WriteProcessMemory_d2f2 {
  strings:
    $key_d2f2 = { 85 80 [2] b7 a2 [2] b1 97 [2] 9f 97 [2] a0 8b }

  condition:
    any of them
}