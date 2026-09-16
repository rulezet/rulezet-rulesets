rule TTP_XOR_WriteProcessMemory_d615 {
  strings:
    $key_d615 = { 81 67 [2] b3 45 [2] b5 70 [2] 9b 70 [2] a4 6c }

  condition:
    any of them
}