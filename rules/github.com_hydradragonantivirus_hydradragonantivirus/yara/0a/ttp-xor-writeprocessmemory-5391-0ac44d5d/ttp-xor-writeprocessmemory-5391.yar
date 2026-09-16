rule TTP_XOR_WriteProcessMemory_5391 {
  strings:
    $key_5391 = { 04 e3 [2] 36 c1 [2] 30 f4 [2] 1e f4 [2] 21 e8 }

  condition:
    any of them
}