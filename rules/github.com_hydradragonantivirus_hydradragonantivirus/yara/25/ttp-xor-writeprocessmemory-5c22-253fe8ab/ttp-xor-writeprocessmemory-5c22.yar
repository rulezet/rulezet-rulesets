rule TTP_XOR_WriteProcessMemory_5c22 {
  strings:
    $key_5c22 = { 0b 50 [2] 39 72 [2] 3f 47 [2] 11 47 [2] 2e 5b }

  condition:
    any of them
}