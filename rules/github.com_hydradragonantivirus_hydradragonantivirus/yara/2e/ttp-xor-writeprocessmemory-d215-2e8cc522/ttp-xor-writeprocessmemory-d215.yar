rule TTP_XOR_WriteProcessMemory_d215 {
  strings:
    $key_d215 = { 85 67 [2] b7 45 [2] b1 70 [2] 9f 70 [2] a0 6c }

  condition:
    any of them
}