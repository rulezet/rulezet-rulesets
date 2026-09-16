rule TTP_XOR_WriteProcessMemory_6043 {
  strings:
    $key_6043 = { 37 31 [2] 05 13 [2] 03 26 [2] 2d 26 [2] 12 3a }

  condition:
    any of them
}