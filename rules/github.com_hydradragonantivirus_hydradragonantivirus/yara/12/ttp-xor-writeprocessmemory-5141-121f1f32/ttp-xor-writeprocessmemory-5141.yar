rule TTP_XOR_WriteProcessMemory_5141 {
  strings:
    $key_5141 = { 06 33 [2] 34 11 [2] 32 24 [2] 1c 24 [2] 23 38 }

  condition:
    any of them
}