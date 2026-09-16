rule TTP_XOR_WriteProcessMemory_6d8c {
  strings:
    $key_6d8c = { 3a fe [2] 08 dc [2] 0e e9 [2] 20 e9 [2] 1f f5 }

  condition:
    any of them
}