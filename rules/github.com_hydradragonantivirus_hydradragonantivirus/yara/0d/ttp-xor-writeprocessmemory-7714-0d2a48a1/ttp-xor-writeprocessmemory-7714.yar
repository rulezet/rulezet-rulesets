rule TTP_XOR_WriteProcessMemory_7714 {
  strings:
    $key_7714 = { 20 66 [2] 12 44 [2] 14 71 [2] 3a 71 [2] 05 6d }

  condition:
    any of them
}