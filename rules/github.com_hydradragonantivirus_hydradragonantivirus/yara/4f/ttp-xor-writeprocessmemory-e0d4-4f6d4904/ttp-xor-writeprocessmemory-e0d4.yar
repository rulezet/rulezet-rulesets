rule TTP_XOR_WriteProcessMemory_e0d4 {
  strings:
    $key_e0d4 = { b7 a6 [2] 85 84 [2] 83 b1 [2] ad b1 [2] 92 ad }

  condition:
    any of them
}