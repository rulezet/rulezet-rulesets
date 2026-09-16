rule TTP_XOR_WriteProcessMemory_7124 {
  strings:
    $key_7124 = { 26 56 [2] 14 74 [2] 12 41 [2] 3c 41 [2] 03 5d }

  condition:
    any of them
}