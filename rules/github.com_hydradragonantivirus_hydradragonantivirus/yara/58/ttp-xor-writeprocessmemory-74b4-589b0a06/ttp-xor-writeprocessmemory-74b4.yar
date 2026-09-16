rule TTP_XOR_WriteProcessMemory_74b4 {
  strings:
    $key_74b4 = { 23 c6 [2] 11 e4 [2] 17 d1 [2] 39 d1 [2] 06 cd }

  condition:
    any of them
}