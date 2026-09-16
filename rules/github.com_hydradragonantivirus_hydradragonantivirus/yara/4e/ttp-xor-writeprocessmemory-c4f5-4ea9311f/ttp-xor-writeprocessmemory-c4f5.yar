rule TTP_XOR_WriteProcessMemory_c4f5 {
  strings:
    $key_c4f5 = { 93 87 [2] a1 a5 [2] a7 90 [2] 89 90 [2] b6 8c }

  condition:
    any of them
}