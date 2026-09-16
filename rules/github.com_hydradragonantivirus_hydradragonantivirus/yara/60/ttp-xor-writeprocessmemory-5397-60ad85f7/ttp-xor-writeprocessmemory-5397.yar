rule TTP_XOR_WriteProcessMemory_5397 {
  strings:
    $key_5397 = { 04 e5 [2] 36 c7 [2] 30 f2 [2] 1e f2 [2] 21 ee }

  condition:
    any of them
}