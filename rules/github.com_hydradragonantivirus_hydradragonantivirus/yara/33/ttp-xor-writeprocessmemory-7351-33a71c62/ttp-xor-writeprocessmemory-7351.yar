rule TTP_XOR_WriteProcessMemory_7351 {
  strings:
    $key_7351 = { 24 23 [2] 16 01 [2] 10 34 [2] 3e 34 [2] 01 28 }

  condition:
    any of them
}