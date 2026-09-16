rule TTP_XOR_WriteProcessMemory_10b4 {
  strings:
    $key_10b4 = { 47 c6 [2] 75 e4 [2] 73 d1 [2] 5d d1 [2] 62 cd }

  condition:
    any of them
}