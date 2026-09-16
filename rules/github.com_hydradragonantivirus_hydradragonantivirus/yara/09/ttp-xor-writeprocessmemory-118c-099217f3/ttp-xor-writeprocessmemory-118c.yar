rule TTP_XOR_WriteProcessMemory_118c {
  strings:
    $key_118c = { 46 fe [2] 74 dc [2] 72 e9 [2] 5c e9 [2] 63 f5 }

  condition:
    any of them
}