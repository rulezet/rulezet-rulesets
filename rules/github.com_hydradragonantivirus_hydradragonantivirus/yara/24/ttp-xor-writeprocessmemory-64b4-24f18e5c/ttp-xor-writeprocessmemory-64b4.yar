rule TTP_XOR_WriteProcessMemory_64b4 {
  strings:
    $key_64b4 = { 33 c6 [2] 01 e4 [2] 07 d1 [2] 29 d1 [2] 16 cd }

  condition:
    any of them
}