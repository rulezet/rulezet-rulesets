rule TTP_XOR_WriteProcessMemory_208c {
  strings:
    $key_208c = { 77 fe [2] 45 dc [2] 43 e9 [2] 6d e9 [2] 52 f5 }

  condition:
    any of them
}