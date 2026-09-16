rule TTP_XOR_WriteProcessMemory_17b1 {
  strings:
    $key_17b1 = { 40 c3 [2] 72 e1 [2] 74 d4 [2] 5a d4 [2] 65 c8 }

  condition:
    any of them
}