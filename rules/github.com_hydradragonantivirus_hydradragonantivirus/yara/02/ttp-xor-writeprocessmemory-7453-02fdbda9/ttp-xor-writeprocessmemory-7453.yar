rule TTP_XOR_WriteProcessMemory_7453 {
  strings:
    $key_7453 = { 23 21 [2] 11 03 [2] 17 36 [2] 39 36 [2] 06 2a }

  condition:
    any of them
}