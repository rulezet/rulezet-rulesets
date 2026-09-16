rule TTP_XOR_WriteProcessMemory_648c {
  strings:
    $key_648c = { 33 fe [2] 01 dc [2] 07 e9 [2] 29 e9 [2] 16 f5 }

  condition:
    any of them
}