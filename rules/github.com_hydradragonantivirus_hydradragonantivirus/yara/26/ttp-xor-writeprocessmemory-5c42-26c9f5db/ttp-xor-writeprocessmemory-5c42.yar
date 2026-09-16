rule TTP_XOR_WriteProcessMemory_5c42 {
  strings:
    $key_5c42 = { 0b 30 [2] 39 12 [2] 3f 27 [2] 11 27 [2] 2e 3b }

  condition:
    any of them
}