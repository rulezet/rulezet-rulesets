rule TTP_XOR_WriteProcessMemory_1663 {
  strings:
    $key_1663 = { 41 11 [2] 73 33 [2] 75 06 [2] 5b 06 [2] 64 1a }

  condition:
    any of them
}