rule TTP_XOR_WriteProcessMemory_5744 {
  strings:
    $key_5744 = { 00 36 [2] 32 14 [2] 34 21 [2] 1a 21 [2] 25 3d }

  condition:
    any of them
}