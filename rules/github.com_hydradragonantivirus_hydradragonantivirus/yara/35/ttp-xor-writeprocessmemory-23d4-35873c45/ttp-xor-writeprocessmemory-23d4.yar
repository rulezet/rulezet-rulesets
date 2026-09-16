rule TTP_XOR_WriteProcessMemory_23d4 {
  strings:
    $key_23d4 = { 74 a6 [2] 46 84 [2] 40 b1 [2] 6e b1 [2] 51 ad }

  condition:
    any of them
}