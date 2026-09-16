rule TTP_XOR_WriteProcessMemory_5764 {
  strings:
    $key_5764 = { 00 16 [2] 32 34 [2] 34 01 [2] 1a 01 [2] 25 1d }

  condition:
    any of them
}