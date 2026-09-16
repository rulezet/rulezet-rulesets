rule TTP_XOR_WriteProcessMemory_2574 {
  strings:
    $key_2574 = { 72 06 [2] 40 24 [2] 46 11 [2] 68 11 [2] 57 0d }

  condition:
    any of them
}