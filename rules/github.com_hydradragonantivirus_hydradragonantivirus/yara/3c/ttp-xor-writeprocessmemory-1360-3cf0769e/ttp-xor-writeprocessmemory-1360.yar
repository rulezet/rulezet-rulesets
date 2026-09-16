rule TTP_XOR_WriteProcessMemory_1360 {
  strings:
    $key_1360 = { 44 12 [2] 76 30 [2] 70 05 [2] 5e 05 [2] 61 19 }

  condition:
    any of them
}