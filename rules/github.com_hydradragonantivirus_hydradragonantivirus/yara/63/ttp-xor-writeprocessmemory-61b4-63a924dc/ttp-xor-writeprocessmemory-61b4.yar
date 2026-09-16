rule TTP_XOR_WriteProcessMemory_61b4 {
  strings:
    $key_61b4 = { 36 c6 [2] 04 e4 [2] 02 d1 [2] 2c d1 [2] 13 cd }

  condition:
    any of them
}