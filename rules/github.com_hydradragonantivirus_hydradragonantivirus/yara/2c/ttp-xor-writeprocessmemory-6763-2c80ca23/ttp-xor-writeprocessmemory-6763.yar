rule TTP_XOR_WriteProcessMemory_6763 {
  strings:
    $key_6763 = { 30 11 [2] 02 33 [2] 04 06 [2] 2a 06 [2] 15 1a }

  condition:
    any of them
}