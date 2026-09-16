rule TTP_XOR_WriteProcessMemory_5f86 {
  strings:
    $key_5f86 = { 08 f4 [2] 3a d6 [2] 3c e3 [2] 12 e3 [2] 2d ff }

  condition:
    any of them
}