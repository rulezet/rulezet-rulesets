rule TTP_XOR_WriteProcessMemory_74b0 {
  strings:
    $key_74b0 = { 23 c2 [2] 11 e0 [2] 17 d5 [2] 39 d5 [2] 06 c9 }

  condition:
    any of them
}