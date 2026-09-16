rule TTP_XOR_WriteProcessMemory_7fa4 {
  strings:
    $key_7fa4 = { 28 d6 [2] 1a f4 [2] 1c c1 [2] 32 c1 [2] 0d dd }

  condition:
    any of them
}