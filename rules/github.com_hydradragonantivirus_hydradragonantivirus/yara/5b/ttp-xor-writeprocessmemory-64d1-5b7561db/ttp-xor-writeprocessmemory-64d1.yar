rule TTP_XOR_WriteProcessMemory_64d1 {
  strings:
    $key_64d1 = { 33 a3 [2] 01 81 [2] 07 b4 [2] 29 b4 [2] 16 a8 }

  condition:
    any of them
}