rule TTP_XOR_WriteProcessMemory_d2f5 {
  strings:
    $key_d2f5 = { 85 87 [2] b7 a5 [2] b1 90 [2] 9f 90 [2] a0 8c }

  condition:
    any of them
}