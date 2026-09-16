rule TTP_XOR_WriteProcessMemory_2f8c {
  strings:
    $key_2f8c = { 78 fe [2] 4a dc [2] 4c e9 [2] 62 e9 [2] 5d f5 }

  condition:
    any of them
}