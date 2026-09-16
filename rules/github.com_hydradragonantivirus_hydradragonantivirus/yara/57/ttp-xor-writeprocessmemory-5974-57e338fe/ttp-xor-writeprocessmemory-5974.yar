rule TTP_XOR_WriteProcessMemory_5974 {
  strings:
    $key_5974 = { 0e 06 [2] 3c 24 [2] 3a 11 [2] 14 11 [2] 2b 0d }

  condition:
    any of them
}