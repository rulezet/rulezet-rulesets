rule TTP_XOR_WriteProcessMemory_7740 {
  strings:
    $key_7740 = { 20 32 [2] 12 10 [2] 14 25 [2] 3a 25 [2] 05 39 }

  condition:
    any of them
}