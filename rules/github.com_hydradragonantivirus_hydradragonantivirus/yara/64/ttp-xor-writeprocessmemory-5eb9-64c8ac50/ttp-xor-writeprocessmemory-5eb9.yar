rule TTP_XOR_WriteProcessMemory_5eb9 {
  strings:
    $key_5eb9 = { 09 cb [2] 3b e9 [2] 3d dc [2] 13 dc [2] 2c c0 }

  condition:
    any of them
}