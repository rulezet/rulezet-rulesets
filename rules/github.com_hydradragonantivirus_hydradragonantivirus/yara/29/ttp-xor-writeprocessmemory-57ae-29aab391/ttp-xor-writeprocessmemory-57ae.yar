rule TTP_XOR_WriteProcessMemory_57ae {
  strings:
    $key_57ae = { 00 dc [2] 32 fe [2] 34 cb [2] 1a cb [2] 25 d7 }

  condition:
    any of them
}