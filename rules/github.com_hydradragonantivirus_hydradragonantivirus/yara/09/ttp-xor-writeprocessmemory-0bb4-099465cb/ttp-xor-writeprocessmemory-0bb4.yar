rule TTP_XOR_WriteProcessMemory_0bb4 {
  strings:
    $key_0bb4 = { 5c c6 [2] 6e e4 [2] 68 d1 [2] 46 d1 [2] 79 cd }

  condition:
    any of them
}