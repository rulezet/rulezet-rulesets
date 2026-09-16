rule TTP_XOR_WriteProcessMemory_62d1 {
  strings:
    $key_62d1 = { 35 a3 [2] 07 81 [2] 01 b4 [2] 2f b4 [2] 10 a8 }

  condition:
    any of them
}