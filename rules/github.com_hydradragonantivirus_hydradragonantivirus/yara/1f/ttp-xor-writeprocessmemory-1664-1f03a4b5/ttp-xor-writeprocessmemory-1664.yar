rule TTP_XOR_WriteProcessMemory_1664 {
  strings:
    $key_1664 = { 41 16 [2] 73 34 [2] 75 01 [2] 5b 01 [2] 64 1d }

  condition:
    any of them
}