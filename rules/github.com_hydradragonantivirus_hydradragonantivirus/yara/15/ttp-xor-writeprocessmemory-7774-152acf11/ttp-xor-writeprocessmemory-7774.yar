rule TTP_XOR_WriteProcessMemory_7774 {
  strings:
    $key_7774 = { 20 06 [2] 12 24 [2] 14 11 [2] 3a 11 [2] 05 0d }

  condition:
    any of them
}