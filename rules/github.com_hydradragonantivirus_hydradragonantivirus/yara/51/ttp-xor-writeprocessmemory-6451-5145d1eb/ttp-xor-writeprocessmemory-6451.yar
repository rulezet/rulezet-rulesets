rule TTP_XOR_WriteProcessMemory_6451 {
  strings:
    $key_6451 = { 33 23 [2] 01 01 [2] 07 34 [2] 29 34 [2] 16 28 }

  condition:
    any of them
}