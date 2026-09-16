rule TTP_XOR_WriteProcessMemory_3e81 {
  strings:
    $key_3e81 = { 69 f3 [2] 5b d1 [2] 5d e4 [2] 73 e4 [2] 4c f8 }

  condition:
    any of them
}