rule TTP_XOR_WriteProcessMemory_2677 {
  strings:
    $key_2677 = { 71 05 [2] 43 27 [2] 45 12 [2] 6b 12 [2] 54 0e }

  condition:
    any of them
}