rule TTP_XOR_WriteProcessMemory_7574 {
  strings:
    $key_7574 = { 22 06 [2] 10 24 [2] 16 11 [2] 38 11 [2] 07 0d }

  condition:
    any of them
}