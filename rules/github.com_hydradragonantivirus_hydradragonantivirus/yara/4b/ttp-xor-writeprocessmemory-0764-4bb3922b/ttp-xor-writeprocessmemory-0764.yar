rule TTP_XOR_WriteProcessMemory_0764 {
  strings:
    $key_0764 = { 50 16 [2] 62 34 [2] 64 01 [2] 4a 01 [2] 75 1d }

  condition:
    any of them
}