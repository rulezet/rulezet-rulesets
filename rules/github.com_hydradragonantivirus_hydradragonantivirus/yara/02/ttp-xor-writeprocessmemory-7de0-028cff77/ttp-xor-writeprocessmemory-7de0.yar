rule TTP_XOR_WriteProcessMemory_7de0 {
  strings:
    $key_7de0 = { 2a 92 [2] 18 b0 [2] 1e 85 [2] 30 85 [2] 0f 99 }

  condition:
    any of them
}