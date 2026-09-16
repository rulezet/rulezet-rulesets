rule TTP_XOR_WriteProcessMemory_45d1 {
  strings:
    $key_45d1 = { 12 a3 [2] 20 81 [2] 26 b4 [2] 08 b4 [2] 37 a8 }

  condition:
    any of them
}