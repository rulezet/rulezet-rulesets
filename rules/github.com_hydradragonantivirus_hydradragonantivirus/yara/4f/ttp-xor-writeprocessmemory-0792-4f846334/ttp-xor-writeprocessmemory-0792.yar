rule TTP_XOR_WriteProcessMemory_0792 {
  strings:
    $key_0792 = { 50 e0 [2] 62 c2 [2] 64 f7 [2] 4a f7 [2] 75 eb }

  condition:
    any of them
}