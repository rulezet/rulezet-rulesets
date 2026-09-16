rule TTP_XOR_WriteProcessMemory_46b4 {
  strings:
    $key_46b4 = { 11 c6 [2] 23 e4 [2] 25 d1 [2] 0b d1 [2] 34 cd }

  condition:
    any of them
}