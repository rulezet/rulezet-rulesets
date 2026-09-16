rule TTP_XOR_WriteProcessMemory_2774 {
  strings:
    $key_2774 = { 70 06 [2] 42 24 [2] 44 11 [2] 6a 11 [2] 55 0d }

  condition:
    any of them
}