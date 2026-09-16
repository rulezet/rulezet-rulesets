rule TTP_XOR_WriteProcessMemory_408c {
  strings:
    $key_408c = { 17 fe [2] 25 dc [2] 23 e9 [2] 0d e9 [2] 32 f5 }

  condition:
    any of them
}