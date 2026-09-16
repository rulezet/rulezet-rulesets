rule TTP_XOR_WriteProcessMemory_5c56 {
  strings:
    $key_5c56 = { 0b 24 [2] 39 06 [2] 3f 33 [2] 11 33 [2] 2e 2f }

  condition:
    any of them
}