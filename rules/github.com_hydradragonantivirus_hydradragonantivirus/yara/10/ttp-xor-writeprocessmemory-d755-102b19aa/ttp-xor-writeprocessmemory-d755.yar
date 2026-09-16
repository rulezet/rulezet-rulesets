rule TTP_XOR_WriteProcessMemory_d755 {
  strings:
    $key_d755 = { 80 27 [2] b2 05 [2] b4 30 [2] 9a 30 [2] a5 2c }

  condition:
    any of them
}