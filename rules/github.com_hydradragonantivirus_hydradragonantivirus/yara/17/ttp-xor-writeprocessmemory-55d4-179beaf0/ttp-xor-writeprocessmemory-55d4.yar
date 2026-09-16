rule TTP_XOR_WriteProcessMemory_55d4 {
  strings:
    $key_55d4 = { 02 a6 [2] 30 84 [2] 36 b1 [2] 18 b1 [2] 27 ad }

  condition:
    any of them
}