rule TTP_XOR_WriteProcessMemory_e0b1 {
  strings:
    $key_e0b1 = { b7 c3 [2] 85 e1 [2] 83 d4 [2] ad d4 [2] 92 c8 }

  condition:
    any of them
}