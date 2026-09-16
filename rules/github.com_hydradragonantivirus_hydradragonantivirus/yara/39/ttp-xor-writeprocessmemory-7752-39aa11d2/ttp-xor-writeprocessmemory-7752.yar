rule TTP_XOR_WriteProcessMemory_7752 {
  strings:
    $key_7752 = { 20 20 [2] 12 02 [2] 14 37 [2] 3a 37 [2] 05 2b }

  condition:
    any of them
}