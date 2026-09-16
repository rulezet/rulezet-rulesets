rule TTP_XOR_WriteProcessMemory_17b4 {
  strings:
    $key_17b4 = { 40 c6 [2] 72 e4 [2] 74 d1 [2] 5a d1 [2] 65 cd }

  condition:
    any of them
}