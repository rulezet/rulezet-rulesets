rule TTP_XOR_WriteProcessMemory_7564 {
  strings:
    $key_7564 = { 22 16 [2] 10 34 [2] 16 01 [2] 38 01 [2] 07 1d }

  condition:
    any of them
}