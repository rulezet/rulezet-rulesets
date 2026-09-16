rule TTP_XOR_WriteProcessMemory_45b4 {
  strings:
    $key_45b4 = { 12 c6 [2] 20 e4 [2] 26 d1 [2] 08 d1 [2] 37 cd }

  condition:
    any of them
}