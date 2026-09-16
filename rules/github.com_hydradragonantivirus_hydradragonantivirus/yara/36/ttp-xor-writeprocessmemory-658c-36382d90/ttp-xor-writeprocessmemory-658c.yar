rule TTP_XOR_WriteProcessMemory_658c {
  strings:
    $key_658c = { 32 fe [2] 00 dc [2] 06 e9 [2] 28 e9 [2] 17 f5 }

  condition:
    any of them
}