rule TTP_XOR_WriteProcessMemory_0063 {
  strings:
    $key_0063 = { 57 11 [2] 65 33 [2] 63 06 [2] 4d 06 [2] 72 1a }

  condition:
    any of them
}