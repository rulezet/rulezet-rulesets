rule TTP_XOR_WriteProcessMemory_5754 {
  strings:
    $key_5754 = { 00 26 [2] 32 04 [2] 34 31 [2] 1a 31 [2] 25 2d }

  condition:
    any of them
}