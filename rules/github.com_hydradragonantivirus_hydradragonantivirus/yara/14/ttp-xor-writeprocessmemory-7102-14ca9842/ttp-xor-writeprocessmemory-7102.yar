rule TTP_XOR_WriteProcessMemory_7102 {
  strings:
    $key_7102 = { 26 70 [2] 14 52 [2] 12 67 [2] 3c 67 [2] 03 7b }

  condition:
    any of them
}