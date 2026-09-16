rule TTP_XOR_WriteProcessMemory_d655 {
  strings:
    $key_d655 = { 81 27 [2] b3 05 [2] b5 30 [2] 9b 30 [2] a4 2c }

  condition:
    any of them
}