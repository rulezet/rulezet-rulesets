rule TTP_XOR_WriteProcessMemory_6674 {
  strings:
    $key_6674 = { 31 06 [2] 03 24 [2] 05 11 [2] 2b 11 [2] 14 0d }

  condition:
    any of them
}