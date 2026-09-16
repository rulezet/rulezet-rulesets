rule TTP_XOR_WriteProcessMemory_63e4 {
  strings:
    $key_63e4 = { 34 96 [2] 06 b4 [2] 00 81 [2] 2e 81 [2] 11 9d }

  condition:
    any of them
}