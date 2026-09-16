rule TTP_XOR_WriteProcessMemory_7f86 {
  strings:
    $key_7f86 = { 28 f4 [2] 1a d6 [2] 1c e3 [2] 32 e3 [2] 0d ff }

  condition:
    any of them
}