rule TTP_XOR_WriteProcessMemory_26d4 {
  strings:
    $key_26d4 = { 71 a6 [2] 43 84 [2] 45 b1 [2] 6b b1 [2] 54 ad }

  condition:
    any of them
}