rule TTP_XOR_WriteProcessMemory_7760 {
  strings:
    $key_7760 = { 20 12 [2] 12 30 [2] 14 05 [2] 3a 05 [2] 05 19 }

  condition:
    any of them
}