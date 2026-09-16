rule TTP_XOR_WriteProcessMemory_02b1 {
  strings:
    $key_02b1 = { 55 c3 [2] 67 e1 [2] 61 d4 [2] 4f d4 [2] 70 c8 }

  condition:
    any of them
}