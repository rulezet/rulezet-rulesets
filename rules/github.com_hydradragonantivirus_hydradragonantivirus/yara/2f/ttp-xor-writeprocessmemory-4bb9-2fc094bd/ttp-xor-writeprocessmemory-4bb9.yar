rule TTP_XOR_WriteProcessMemory_4bb9 {
  strings:
    $key_4bb9 = { 1c cb [2] 2e e9 [2] 28 dc [2] 06 dc [2] 39 c0 }

  condition:
    any of them
}