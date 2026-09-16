rule TTP_XOR_WriteProcessMemory_0f8c {
  strings:
    $key_0f8c = { 58 fe [2] 6a dc [2] 6c e9 [2] 42 e9 [2] 7d f5 }

  condition:
    any of them
}