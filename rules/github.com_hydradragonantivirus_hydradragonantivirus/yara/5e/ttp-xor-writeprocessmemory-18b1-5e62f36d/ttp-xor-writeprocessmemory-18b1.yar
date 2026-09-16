rule TTP_XOR_WriteProcessMemory_18b1 {
  strings:
    $key_18b1 = { 4f c3 [2] 7d e1 [2] 7b d4 [2] 55 d4 [2] 6a c8 }

  condition:
    any of them
}