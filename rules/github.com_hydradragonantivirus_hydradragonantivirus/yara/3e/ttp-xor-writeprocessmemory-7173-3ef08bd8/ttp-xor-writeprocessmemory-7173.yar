rule TTP_XOR_WriteProcessMemory_7173 {
  strings:
    $key_7173 = { 26 01 [2] 14 23 [2] 12 16 [2] 3c 16 [2] 03 0a }

  condition:
    any of them
}