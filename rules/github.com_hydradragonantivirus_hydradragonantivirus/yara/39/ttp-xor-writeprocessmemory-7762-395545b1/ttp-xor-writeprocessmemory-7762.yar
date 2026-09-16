rule TTP_XOR_WriteProcessMemory_7762 {
  strings:
    $key_7762 = { 20 10 [2] 12 32 [2] 14 07 [2] 3a 07 [2] 05 1b }

  condition:
    any of them
}