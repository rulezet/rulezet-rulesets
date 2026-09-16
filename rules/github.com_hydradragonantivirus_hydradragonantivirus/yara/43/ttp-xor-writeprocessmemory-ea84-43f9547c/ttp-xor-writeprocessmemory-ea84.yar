rule TTP_XOR_WriteProcessMemory_ea84 {
  strings:
    $key_ea84 = { bd f6 [2] 8f d4 [2] 89 e1 [2] a7 e1 [2] 98 fd }

  condition:
    any of them
}