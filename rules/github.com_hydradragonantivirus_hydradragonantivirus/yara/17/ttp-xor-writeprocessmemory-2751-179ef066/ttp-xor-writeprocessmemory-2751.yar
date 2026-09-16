rule TTP_XOR_WriteProcessMemory_2751 {
  strings:
    $key_2751 = { 70 23 [2] 42 01 [2] 44 34 [2] 6a 34 [2] 55 28 }

  condition:
    any of them
}