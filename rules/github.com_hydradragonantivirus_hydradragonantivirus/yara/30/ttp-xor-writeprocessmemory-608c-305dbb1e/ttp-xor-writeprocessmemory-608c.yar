rule TTP_XOR_WriteProcessMemory_608c {
  strings:
    $key_608c = { 37 fe [2] 05 dc [2] 03 e9 [2] 2d e9 [2] 12 f5 }

  condition:
    any of them
}