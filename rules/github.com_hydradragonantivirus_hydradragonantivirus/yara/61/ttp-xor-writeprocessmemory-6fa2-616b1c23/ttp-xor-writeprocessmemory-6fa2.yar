rule TTP_XOR_WriteProcessMemory_6fa2 {
  strings:
    $key_6fa2 = { 38 d0 [2] 0a f2 [2] 0c c7 [2] 22 c7 [2] 1d db }

  condition:
    any of them
}