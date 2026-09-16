rule TTP_XOR_WriteProcessMemory_638c {
  strings:
    $key_638c = { 34 fe [2] 06 dc [2] 00 e9 [2] 2e e9 [2] 11 f5 }

  condition:
    any of them
}