rule TTP_XOR_WriteProcessMemory_3ba5 {
  strings:
    $key_3ba5 = { 6c d7 [2] 5e f5 [2] 58 c0 [2] 76 c0 [2] 49 dc }

  condition:
    any of them
}