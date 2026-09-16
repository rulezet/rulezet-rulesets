rule TTP_XOR_WriteProcessMemory_6bb4 {
  strings:
    $key_6bb4 = { 3c c6 [2] 0e e4 [2] 08 d1 [2] 26 d1 [2] 19 cd }

  condition:
    any of them
}