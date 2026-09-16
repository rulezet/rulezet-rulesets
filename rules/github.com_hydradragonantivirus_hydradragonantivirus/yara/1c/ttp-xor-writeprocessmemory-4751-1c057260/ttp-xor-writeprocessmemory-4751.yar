rule TTP_XOR_WriteProcessMemory_4751 {
  strings:
    $key_4751 = { 10 23 [2] 22 01 [2] 24 34 [2] 0a 34 [2] 35 28 }

  condition:
    any of them
}