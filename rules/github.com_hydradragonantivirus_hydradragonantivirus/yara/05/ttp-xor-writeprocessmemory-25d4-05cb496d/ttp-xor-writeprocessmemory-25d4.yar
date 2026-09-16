rule TTP_XOR_WriteProcessMemory_25d4 {
  strings:
    $key_25d4 = { 72 a6 [2] 40 84 [2] 46 b1 [2] 68 b1 [2] 57 ad }

  condition:
    any of them
}