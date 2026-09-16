rule TTP_XOR_WriteProcessMemory_74b1 {
  strings:
    $key_74b1 = { 23 c3 [2] 11 e1 [2] 17 d4 [2] 39 d4 [2] 06 c8 }

  condition:
    any of them
}