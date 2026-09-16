rule TTP_XOR_WriteProcessMemory_3991 {
  strings:
    $key_3991 = { 6e e3 [2] 5c c1 [2] 5a f4 [2] 74 f4 [2] 4b e8 }

  condition:
    any of them
}