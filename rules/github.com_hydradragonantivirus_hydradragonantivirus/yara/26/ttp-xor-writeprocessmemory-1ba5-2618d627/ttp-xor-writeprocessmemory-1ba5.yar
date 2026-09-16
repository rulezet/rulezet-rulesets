rule TTP_XOR_WriteProcessMemory_1ba5 {
  strings:
    $key_1ba5 = { 4c d7 [2] 7e f5 [2] 78 c0 [2] 56 c0 [2] 69 dc }

  condition:
    any of them
}