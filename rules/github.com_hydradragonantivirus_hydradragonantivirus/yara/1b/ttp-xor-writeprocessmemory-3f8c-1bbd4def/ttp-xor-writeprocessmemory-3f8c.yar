rule TTP_XOR_WriteProcessMemory_3f8c {
  strings:
    $key_3f8c = { 68 fe [2] 5a dc [2] 5c e9 [2] 72 e9 [2] 4d f5 }

  condition:
    any of them
}