rule TTP_XOR_WriteProcessMemory_1d8c {
  strings:
    $key_1d8c = { 4a fe [2] 78 dc [2] 7e e9 [2] 50 e9 [2] 6f f5 }

  condition:
    any of them
}