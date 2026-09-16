rule TTP_XOR_WriteProcessMemory_4eb9 {
  strings:
    $key_4eb9 = { 19 cb [2] 2b e9 [2] 2d dc [2] 03 dc [2] 3c c0 }

  condition:
    any of them
}