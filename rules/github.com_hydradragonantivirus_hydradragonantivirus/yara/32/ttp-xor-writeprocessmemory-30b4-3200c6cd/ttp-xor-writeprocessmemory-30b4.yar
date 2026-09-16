rule TTP_XOR_WriteProcessMemory_30b4 {
  strings:
    $key_30b4 = { 67 c6 [2] 55 e4 [2] 53 d1 [2] 7d d1 [2] 42 cd }

  condition:
    any of them
}