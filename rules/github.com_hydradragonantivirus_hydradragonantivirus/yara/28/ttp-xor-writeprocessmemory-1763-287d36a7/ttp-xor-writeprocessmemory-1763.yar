rule TTP_XOR_WriteProcessMemory_1763 {
  strings:
    $key_1763 = { 40 11 [2] 72 33 [2] 74 06 [2] 5a 06 [2] 65 1a }

  condition:
    any of them
}