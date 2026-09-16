rule TTP_XOR_WriteProcessMemory_1f8c {
  strings:
    $key_1f8c = { 48 fe [2] 7a dc [2] 7c e9 [2] 52 e9 [2] 6d f5 }

  condition:
    any of them
}