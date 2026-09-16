rule TTP_XOR_WriteProcessMemory_d6f5 {
  strings:
    $key_d6f5 = { 81 87 [2] b3 a5 [2] b5 90 [2] 9b 90 [2] a4 8c }

  condition:
    any of them
}