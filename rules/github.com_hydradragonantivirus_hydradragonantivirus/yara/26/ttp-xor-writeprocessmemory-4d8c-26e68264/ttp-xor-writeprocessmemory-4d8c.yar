rule TTP_XOR_WriteProcessMemory_4d8c {
  strings:
    $key_4d8c = { 1a fe [2] 28 dc [2] 2e e9 [2] 00 e9 [2] 3f f5 }

  condition:
    any of them
}