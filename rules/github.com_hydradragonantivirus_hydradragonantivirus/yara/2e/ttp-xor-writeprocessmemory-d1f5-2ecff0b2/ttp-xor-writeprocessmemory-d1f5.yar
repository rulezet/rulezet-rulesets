rule TTP_XOR_WriteProcessMemory_d1f5 {
  strings:
    $key_d1f5 = { 86 87 [2] b4 a5 [2] b2 90 [2] 9c 90 [2] a3 8c }

  condition:
    any of them
}