rule TTP_XOR_WriteProcessMemory_25d1 {
  strings:
    $key_25d1 = { 72 a3 [2] 40 81 [2] 46 b4 [2] 68 b4 [2] 57 a8 }

  condition:
    any of them
}