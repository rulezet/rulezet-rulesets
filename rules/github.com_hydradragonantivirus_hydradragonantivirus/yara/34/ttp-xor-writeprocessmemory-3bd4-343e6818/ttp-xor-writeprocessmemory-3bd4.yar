rule TTP_XOR_WriteProcessMemory_3bd4 {
  strings:
    $key_3bd4 = { 6c a6 [2] 5e 84 [2] 58 b1 [2] 76 b1 [2] 49 ad }

  condition:
    any of them
}