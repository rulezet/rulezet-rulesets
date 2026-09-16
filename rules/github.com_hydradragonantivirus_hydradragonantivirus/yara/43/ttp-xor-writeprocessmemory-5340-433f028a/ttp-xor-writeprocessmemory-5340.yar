rule TTP_XOR_WriteProcessMemory_5340 {
  strings:
    $key_5340 = { 04 32 [2] 36 10 [2] 30 25 [2] 1e 25 [2] 21 39 }

  condition:
    any of them
}