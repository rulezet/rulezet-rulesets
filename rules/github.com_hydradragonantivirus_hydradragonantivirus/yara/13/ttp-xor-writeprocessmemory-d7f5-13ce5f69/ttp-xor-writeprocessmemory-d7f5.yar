rule TTP_XOR_WriteProcessMemory_d7f5 {
  strings:
    $key_d7f5 = { 80 87 [2] b2 a5 [2] b4 90 [2] 9a 90 [2] a5 8c }

  condition:
    any of them
}