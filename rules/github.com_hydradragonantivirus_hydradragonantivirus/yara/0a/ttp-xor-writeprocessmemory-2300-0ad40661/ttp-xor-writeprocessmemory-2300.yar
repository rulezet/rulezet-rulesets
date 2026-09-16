rule TTP_XOR_WriteProcessMemory_2300 {
  strings:
    $key_2300 = { 74 72 [2] 46 50 [2] 40 65 [2] 6e 65 [2] 51 79 }

  condition:
    any of them
}