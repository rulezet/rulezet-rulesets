rule TTP_XOR_WriteProcessMemory_2763 {
  strings:
    $key_2763 = { 70 11 [2] 42 33 [2] 44 06 [2] 6a 06 [2] 55 1a }

  condition:
    any of them
}