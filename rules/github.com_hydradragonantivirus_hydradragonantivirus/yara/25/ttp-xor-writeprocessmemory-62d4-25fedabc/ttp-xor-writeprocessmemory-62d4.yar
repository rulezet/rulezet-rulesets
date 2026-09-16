rule TTP_XOR_WriteProcessMemory_62d4 {
  strings:
    $key_62d4 = { 35 a6 [2] 07 84 [2] 01 b1 [2] 2f b1 [2] 10 ad }

  condition:
    any of them
}