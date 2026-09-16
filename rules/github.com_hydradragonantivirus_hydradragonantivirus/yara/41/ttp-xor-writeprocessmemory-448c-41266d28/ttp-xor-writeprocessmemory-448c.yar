rule TTP_XOR_WriteProcessMemory_448c {
  strings:
    $key_448c = { 13 fe [2] 21 dc [2] 27 e9 [2] 09 e9 [2] 36 f5 }

  condition:
    any of them
}