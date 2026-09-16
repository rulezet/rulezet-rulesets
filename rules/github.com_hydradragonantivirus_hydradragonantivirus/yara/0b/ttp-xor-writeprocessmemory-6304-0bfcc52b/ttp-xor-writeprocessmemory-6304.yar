rule TTP_XOR_WriteProcessMemory_6304 {
  strings:
    $key_6304 = { 34 76 [2] 06 54 [2] 00 61 [2] 2e 61 [2] 11 7d }

  condition:
    any of them
}