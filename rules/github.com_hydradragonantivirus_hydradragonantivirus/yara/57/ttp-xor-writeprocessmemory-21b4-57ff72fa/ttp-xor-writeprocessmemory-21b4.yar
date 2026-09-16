rule TTP_XOR_WriteProcessMemory_21b4 {
  strings:
    $key_21b4 = { 76 c6 [2] 44 e4 [2] 42 d1 [2] 6c d1 [2] 53 cd }

  condition:
    any of them
}