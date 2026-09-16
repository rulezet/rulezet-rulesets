rule TTP_XOR_WriteProcessMemory_30a7 {
  strings:
    $key_30a7 = { 67 d5 [2] 55 f7 [2] 53 c2 [2] 7d c2 [2] 42 de }

  condition:
    any of them
}