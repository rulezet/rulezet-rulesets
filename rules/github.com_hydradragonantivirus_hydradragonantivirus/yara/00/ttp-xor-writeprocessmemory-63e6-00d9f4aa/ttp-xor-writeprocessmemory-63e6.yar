rule TTP_XOR_WriteProcessMemory_63e6 {
  strings:
    $key_63e6 = { 34 94 [2] 06 b6 [2] 00 83 [2] 2e 83 [2] 11 9f }

  condition:
    any of them
}