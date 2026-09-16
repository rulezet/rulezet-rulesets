rule TTP_XOR_WriteProcessMemory_3441 {
  strings:
    $key_3441 = { 63 33 [2] 51 11 [2] 57 24 [2] 79 24 [2] 46 38 }

  condition:
    any of them
}