rule TTP_XOR_WriteProcessMemory_0740 {
  strings:
    $key_0740 = { 50 32 [2] 62 10 [2] 64 25 [2] 4a 25 [2] 75 39 }

  condition:
    any of them
}