rule TTP_XOR_WriteProcessMemory_6bd1 {
  strings:
    $key_6bd1 = { 3c a3 [2] 0e 81 [2] 08 b4 [2] 26 b4 [2] 19 a8 }

  condition:
    any of them
}