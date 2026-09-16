rule TTP_XOR_WriteProcessMemory_7743 {
  strings:
    $key_7743 = { 20 31 [2] 12 13 [2] 14 26 [2] 3a 26 [2] 05 3a }

  condition:
    any of them
}