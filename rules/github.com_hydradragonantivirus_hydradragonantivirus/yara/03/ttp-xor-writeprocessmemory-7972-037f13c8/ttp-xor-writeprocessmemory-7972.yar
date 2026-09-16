rule TTP_XOR_WriteProcessMemory_7972 {
  strings:
    $key_7972 = { 2e 00 [2] 1c 22 [2] 1a 17 [2] 34 17 [2] 0b 0b }

  condition:
    any of them
}