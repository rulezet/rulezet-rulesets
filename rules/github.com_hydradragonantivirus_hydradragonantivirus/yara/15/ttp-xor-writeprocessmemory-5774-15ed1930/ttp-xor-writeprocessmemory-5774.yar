rule TTP_XOR_WriteProcessMemory_5774 {
  strings:
    $key_5774 = { 00 06 [2] 32 24 [2] 34 11 [2] 1a 11 [2] 25 0d }

  condition:
    any of them
}