rule TTP_XOR_WriteProcessMemory_5341 {
  strings:
    $key_5341 = { 04 33 [2] 36 11 [2] 30 24 [2] 1e 24 [2] 21 38 }

  condition:
    any of them
}