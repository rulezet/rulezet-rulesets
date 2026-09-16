rule TTP_XOR_WriteProcessMemory_518c {
  strings:
    $key_518c = { 06 fe [2] 34 dc [2] 32 e9 [2] 1c e9 [2] 23 f5 }

  condition:
    any of them
}