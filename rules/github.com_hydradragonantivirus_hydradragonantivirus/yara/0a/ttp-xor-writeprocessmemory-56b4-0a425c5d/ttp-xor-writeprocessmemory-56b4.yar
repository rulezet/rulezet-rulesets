rule TTP_XOR_WriteProcessMemory_56b4 {
  strings:
    $key_56b4 = { 01 c6 [2] 33 e4 [2] 35 d1 [2] 1b d1 [2] 24 cd }

  condition:
    any of them
}