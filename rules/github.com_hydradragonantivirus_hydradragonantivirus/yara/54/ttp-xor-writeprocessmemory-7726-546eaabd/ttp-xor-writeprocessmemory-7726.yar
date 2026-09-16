rule TTP_XOR_WriteProcessMemory_7726 {
  strings:
    $key_7726 = { 20 54 [2] 12 76 [2] 14 43 [2] 3a 43 [2] 05 5f }

  condition:
    any of them
}