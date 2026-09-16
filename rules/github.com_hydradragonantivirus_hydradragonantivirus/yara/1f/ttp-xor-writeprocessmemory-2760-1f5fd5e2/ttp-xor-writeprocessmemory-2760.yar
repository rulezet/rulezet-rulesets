rule TTP_XOR_WriteProcessMemory_2760 {
  strings:
    $key_2760 = { 70 12 [2] 42 30 [2] 44 05 [2] 6a 05 [2] 55 19 }

  condition:
    any of them
}