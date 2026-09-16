rule TTP_XOR_WriteProcessMemory_10b1 {
  strings:
    $key_10b1 = { 47 c3 [2] 75 e1 [2] 73 d4 [2] 5d d4 [2] 62 c8 }

  condition:
    any of them
}