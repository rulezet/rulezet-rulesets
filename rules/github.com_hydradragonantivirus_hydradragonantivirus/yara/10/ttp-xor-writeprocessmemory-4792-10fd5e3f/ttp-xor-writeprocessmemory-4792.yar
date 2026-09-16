rule TTP_XOR_WriteProcessMemory_4792 {
  strings:
    $key_4792 = { 10 e0 [2] 22 c2 [2] 24 f7 [2] 0a f7 [2] 35 eb }

  condition:
    any of them
}