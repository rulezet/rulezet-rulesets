rule TTP_XOR_WriteProcessMemory_018c {
  strings:
    $key_018c = { 56 fe [2] 64 dc [2] 62 e9 [2] 4c e9 [2] 73 f5 }

  condition:
    any of them
}