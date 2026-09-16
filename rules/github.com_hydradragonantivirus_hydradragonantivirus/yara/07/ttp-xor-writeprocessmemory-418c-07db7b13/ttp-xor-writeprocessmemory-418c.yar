rule TTP_XOR_WriteProcessMemory_418c {
  strings:
    $key_418c = { 16 fe [2] 24 dc [2] 22 e9 [2] 0c e9 [2] 33 f5 }

  condition:
    any of them
}