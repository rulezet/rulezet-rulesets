rule TTP_XOR_WriteProcessMemory_4ab4 {
  strings:
    $key_4ab4 = { 1d c6 [2] 2f e4 [2] 29 d1 [2] 07 d1 [2] 38 cd }

  condition:
    any of them
}