rule TTP_XOR_WriteProcessMemory_1960 {
  strings:
    $key_1960 = { 4e 12 [2] 7c 30 [2] 7a 05 [2] 54 05 [2] 6b 19 }

  condition:
    any of them
}