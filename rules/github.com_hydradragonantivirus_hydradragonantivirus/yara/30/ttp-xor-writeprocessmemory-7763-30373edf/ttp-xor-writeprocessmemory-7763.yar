rule TTP_XOR_WriteProcessMemory_7763 {
  strings:
    $key_7763 = { 20 11 [2] 12 33 [2] 14 06 [2] 3a 06 [2] 05 1a }

  condition:
    any of them
}