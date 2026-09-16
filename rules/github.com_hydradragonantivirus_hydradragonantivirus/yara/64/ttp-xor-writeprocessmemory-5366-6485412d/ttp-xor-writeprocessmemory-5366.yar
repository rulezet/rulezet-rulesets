rule TTP_XOR_WriteProcessMemory_5366 {
  strings:
    $key_5366 = { 04 14 [2] 36 36 [2] 30 03 [2] 1e 03 [2] 21 1f }

  condition:
    any of them
}