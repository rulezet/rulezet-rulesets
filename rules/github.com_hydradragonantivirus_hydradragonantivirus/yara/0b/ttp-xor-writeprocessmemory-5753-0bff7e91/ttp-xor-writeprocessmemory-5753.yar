rule TTP_XOR_WriteProcessMemory_5753 {
  strings:
    $key_5753 = { 00 21 [2] 32 03 [2] 34 36 [2] 1a 36 [2] 25 2a }

  condition:
    any of them
}