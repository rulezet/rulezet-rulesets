rule TTP_XOR_WriteProcessMemory_40b4 {
  strings:
    $key_40b4 = { 17 c6 [2] 25 e4 [2] 23 d1 [2] 0d d1 [2] 32 cd }

  condition:
    any of them
}