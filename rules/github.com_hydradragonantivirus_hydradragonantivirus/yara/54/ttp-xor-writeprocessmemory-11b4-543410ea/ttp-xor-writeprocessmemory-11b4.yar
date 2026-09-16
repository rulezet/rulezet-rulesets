rule TTP_XOR_WriteProcessMemory_11b4 {
  strings:
    $key_11b4 = { 46 c6 [2] 74 e4 [2] 72 d1 [2] 5c d1 [2] 63 cd }

  condition:
    any of them
}