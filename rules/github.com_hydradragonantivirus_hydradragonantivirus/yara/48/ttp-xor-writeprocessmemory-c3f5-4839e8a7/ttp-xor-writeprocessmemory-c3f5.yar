rule TTP_XOR_WriteProcessMemory_c3f5 {
  strings:
    $key_c3f5 = { 94 87 [2] a6 a5 [2] a0 90 [2] 8e 90 [2] b1 8c }

  condition:
    any of them
}