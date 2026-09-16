rule TTP_XOR_WriteProcessMemory_7172 {
  strings:
    $key_7172 = { 26 00 [2] 14 22 [2] 12 17 [2] 3c 17 [2] 03 0b }

  condition:
    any of them
}