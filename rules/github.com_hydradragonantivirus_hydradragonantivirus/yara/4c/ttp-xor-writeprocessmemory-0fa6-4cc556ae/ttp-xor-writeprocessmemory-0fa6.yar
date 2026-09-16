rule TTP_XOR_WriteProcessMemory_0fa6 {
  strings:
    $key_0fa6 = { 58 d4 [2] 6a f6 [2] 6c c3 [2] 42 c3 [2] 7d df }

  condition:
    any of them
}