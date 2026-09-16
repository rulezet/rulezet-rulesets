rule TTP_XOR_WriteProcessMemory_c715 {
  strings:
    $key_c715 = { 90 67 [2] a2 45 [2] a4 70 [2] 8a 70 [2] b5 6c }

  condition:
    any of them
}