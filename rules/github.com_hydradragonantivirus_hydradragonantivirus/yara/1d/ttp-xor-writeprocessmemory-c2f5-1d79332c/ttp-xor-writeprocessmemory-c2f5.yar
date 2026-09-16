rule TTP_XOR_WriteProcessMemory_c2f5 {
  strings:
    $key_c2f5 = { 95 87 [2] a7 a5 [2] a1 90 [2] 8f 90 [2] b0 8c }

  condition:
    any of them
}