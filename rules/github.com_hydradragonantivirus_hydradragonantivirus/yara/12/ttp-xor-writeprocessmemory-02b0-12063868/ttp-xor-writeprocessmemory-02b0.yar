rule TTP_XOR_WriteProcessMemory_02b0 {
  strings:
    $key_02b0 = { 55 c2 [2] 67 e0 [2] 61 d5 [2] 4f d5 [2] 70 c9 }

  condition:
    any of them
}