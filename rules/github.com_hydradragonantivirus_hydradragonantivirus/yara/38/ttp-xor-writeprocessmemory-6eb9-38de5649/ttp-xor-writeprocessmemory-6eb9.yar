rule TTP_XOR_WriteProcessMemory_6eb9 {
  strings:
    $key_6eb9 = { 39 cb [2] 0b e9 [2] 0d dc [2] 23 dc [2] 1c c0 }

  condition:
    any of them
}