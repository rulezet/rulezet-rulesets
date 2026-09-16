rule TTP_XOR_WriteProcessMemory_568c {
  strings:
    $key_568c = { 01 fe [2] 33 dc [2] 35 e9 [2] 1b e9 [2] 24 f5 }

  condition:
    any of them
}