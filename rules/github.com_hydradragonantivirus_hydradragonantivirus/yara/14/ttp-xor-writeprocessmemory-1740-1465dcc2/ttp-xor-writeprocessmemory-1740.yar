rule TTP_XOR_WriteProcessMemory_1740 {
  strings:
    $key_1740 = { 40 32 [2] 72 10 [2] 74 25 [2] 5a 25 [2] 65 39 }

  condition:
    any of them
}