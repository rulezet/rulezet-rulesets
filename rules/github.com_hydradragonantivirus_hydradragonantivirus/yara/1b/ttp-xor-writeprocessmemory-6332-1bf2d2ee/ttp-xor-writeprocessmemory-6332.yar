rule TTP_XOR_WriteProcessMemory_6332 {
  strings:
    $key_6332 = { 34 40 [2] 06 62 [2] 00 57 [2] 2e 57 [2] 11 4b }

  condition:
    any of them
}