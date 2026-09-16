rule TTP_XOR_WriteProcessMemory_0751 {
  strings:
    $key_0751 = { 50 23 [2] 62 01 [2] 64 34 [2] 4a 34 [2] 75 28 }

  condition:
    any of them
}