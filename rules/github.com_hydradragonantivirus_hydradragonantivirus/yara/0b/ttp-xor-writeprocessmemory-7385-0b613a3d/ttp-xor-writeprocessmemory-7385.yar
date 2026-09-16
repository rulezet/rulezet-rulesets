rule TTP_XOR_WriteProcessMemory_7385 {
  strings:
    $key_7385 = { 24 f7 [2] 16 d5 [2] 10 e0 [2] 3e e0 [2] 01 fc }

  condition:
    any of them
}