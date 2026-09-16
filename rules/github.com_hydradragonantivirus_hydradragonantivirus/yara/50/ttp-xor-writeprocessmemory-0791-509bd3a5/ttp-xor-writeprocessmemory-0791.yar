rule TTP_XOR_WriteProcessMemory_0791 {
  strings:
    $key_0791 = { 50 e3 [2] 62 c1 [2] 64 f4 [2] 4a f4 [2] 75 e8 }

  condition:
    any of them
}