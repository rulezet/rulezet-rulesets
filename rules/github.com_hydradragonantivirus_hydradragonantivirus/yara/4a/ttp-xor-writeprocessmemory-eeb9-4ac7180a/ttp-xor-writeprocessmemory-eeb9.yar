rule TTP_XOR_WriteProcessMemory_eeb9 {
  strings:
    $key_eeb9 = { b9 cb [2] 8b e9 [2] 8d dc [2] a3 dc [2] 9c c0 }

  condition:
    any of them
}