rule TTP_XOR_WriteProcessMemory_4bb4 {
  strings:
    $key_4bb4 = { 1c c6 [2] 2e e4 [2] 28 d1 [2] 06 d1 [2] 39 cd }

  condition:
    any of them
}