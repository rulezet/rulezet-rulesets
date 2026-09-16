rule TTP_XOR_WriteProcessMemory_e0b4 {
  strings:
    $key_e0b4 = { b7 c6 [2] 85 e4 [2] 83 d1 [2] ad d1 [2] 92 cd }

  condition:
    any of them
}