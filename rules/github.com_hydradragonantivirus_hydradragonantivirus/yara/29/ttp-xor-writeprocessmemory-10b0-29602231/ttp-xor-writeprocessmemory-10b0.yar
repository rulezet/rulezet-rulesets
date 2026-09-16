rule TTP_XOR_WriteProcessMemory_10b0 {
  strings:
    $key_10b0 = { 47 c2 [2] 75 e0 [2] 73 d5 [2] 5d d5 [2] 62 c9 }

  condition:
    any of them
}