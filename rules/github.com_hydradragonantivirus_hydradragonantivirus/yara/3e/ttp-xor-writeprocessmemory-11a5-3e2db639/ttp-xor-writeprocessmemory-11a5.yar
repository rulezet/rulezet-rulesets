rule TTP_XOR_WriteProcessMemory_11a5 {
  strings:
    $key_11a5 = { 46 d7 [2] 74 f5 [2] 72 c0 [2] 5c c0 [2] 63 dc }

  condition:
    any of them
}