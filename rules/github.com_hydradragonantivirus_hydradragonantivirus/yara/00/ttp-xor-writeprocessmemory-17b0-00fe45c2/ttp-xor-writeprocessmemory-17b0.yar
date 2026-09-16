rule TTP_XOR_WriteProcessMemory_17b0 {
  strings:
    $key_17b0 = { 40 c2 [2] 72 e0 [2] 74 d5 [2] 5a d5 [2] 65 c9 }

  condition:
    any of them
}