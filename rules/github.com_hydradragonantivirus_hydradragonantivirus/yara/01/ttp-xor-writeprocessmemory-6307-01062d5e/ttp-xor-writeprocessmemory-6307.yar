rule TTP_XOR_WriteProcessMemory_6307 {
  strings:
    $key_6307 = { 34 75 [2] 06 57 [2] 00 62 [2] 2e 62 [2] 11 7e }

  condition:
    any of them
}