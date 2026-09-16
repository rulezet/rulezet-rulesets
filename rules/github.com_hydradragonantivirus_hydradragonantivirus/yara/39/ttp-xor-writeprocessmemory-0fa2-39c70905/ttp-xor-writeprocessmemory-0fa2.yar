rule TTP_XOR_WriteProcessMemory_0fa2 {
  strings:
    $key_0fa2 = { 58 d0 [2] 6a f2 [2] 6c c7 [2] 42 c7 [2] 7d db }

  condition:
    any of them
}