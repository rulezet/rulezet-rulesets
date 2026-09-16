rule TTP_XOR_WriteProcessMemory_2660 {
  strings:
    $key_2660 = { 71 12 [2] 43 30 [2] 45 05 [2] 6b 05 [2] 54 19 }

  condition:
    any of them
}