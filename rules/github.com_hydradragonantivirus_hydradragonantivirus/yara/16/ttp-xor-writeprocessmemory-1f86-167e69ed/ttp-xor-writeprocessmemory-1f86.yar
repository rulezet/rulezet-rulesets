rule TTP_XOR_WriteProcessMemory_1f86 {
  strings:
    $key_1f86 = { 48 f4 [2] 7a d6 [2] 7c e3 [2] 52 e3 [2] 6d ff }

  condition:
    any of them
}