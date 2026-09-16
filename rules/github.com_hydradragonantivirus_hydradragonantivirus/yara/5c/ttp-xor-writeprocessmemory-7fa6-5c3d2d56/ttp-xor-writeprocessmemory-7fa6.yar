rule TTP_XOR_WriteProcessMemory_7fa6 {
  strings:
    $key_7fa6 = { 28 d4 [2] 1a f6 [2] 1c c3 [2] 32 c3 [2] 0d df }

  condition:
    any of them
}