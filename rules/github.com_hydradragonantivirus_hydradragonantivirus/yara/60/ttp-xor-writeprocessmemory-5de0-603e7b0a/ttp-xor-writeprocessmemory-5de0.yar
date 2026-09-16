rule TTP_XOR_WriteProcessMemory_5de0 {
  strings:
    $key_5de0 = { 0a 92 [2] 38 b0 [2] 3e 85 [2] 10 85 [2] 2f 99 }

  condition:
    any of them
}