rule TTP_XOR_WriteProcessMemory_13a5 {
  strings:
    $key_13a5 = { 44 d7 [2] 76 f5 [2] 70 c0 [2] 5e c0 [2] 61 dc }

  condition:
    any of them
}