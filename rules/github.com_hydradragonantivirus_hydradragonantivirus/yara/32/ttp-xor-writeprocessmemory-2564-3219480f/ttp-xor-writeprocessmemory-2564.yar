rule TTP_XOR_WriteProcessMemory_2564 {
  strings:
    $key_2564 = { 72 16 [2] 40 34 [2] 46 01 [2] 68 01 [2] 57 1d }

  condition:
    any of them
}