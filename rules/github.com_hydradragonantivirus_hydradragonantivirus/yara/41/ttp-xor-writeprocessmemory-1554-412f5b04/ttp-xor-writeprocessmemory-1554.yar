rule TTP_XOR_WriteProcessMemory_1554 {
  strings:
    $key_1554 = { 42 26 [2] 70 04 [2] 76 31 [2] 58 31 [2] 67 2d }

  condition:
    any of them
}