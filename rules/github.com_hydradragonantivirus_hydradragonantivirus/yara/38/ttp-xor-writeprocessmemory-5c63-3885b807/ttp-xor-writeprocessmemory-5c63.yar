rule TTP_XOR_WriteProcessMemory_5c63 {
  strings:
    $key_5c63 = { 0b 11 [2] 39 33 [2] 3f 06 [2] 11 06 [2] 2e 1a }

  condition:
    any of them
}