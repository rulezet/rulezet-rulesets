rule TTP_XOR_WriteProcessMemory_7532 {
  strings:
    $key_7532 = { 22 40 [2] 10 62 [2] 16 57 [2] 38 57 [2] 07 4b }

  condition:
    any of them
}