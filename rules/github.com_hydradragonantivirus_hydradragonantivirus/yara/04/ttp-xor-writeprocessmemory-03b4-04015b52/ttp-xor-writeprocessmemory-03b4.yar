rule TTP_XOR_WriteProcessMemory_03b4 {
  strings:
    $key_03b4 = { 54 c6 [2] 66 e4 [2] 60 d1 [2] 4e d1 [2] 71 cd }

  condition:
    any of them
}