rule TTP_XOR_WriteProcessMemory_13d4 {
  strings:
    $key_13d4 = { 44 a6 [2] 76 84 [2] 70 b1 [2] 5e b1 [2] 61 ad }

  condition:
    any of them
}