rule TTP_XOR_WriteProcessMemory_3f86 {
  strings:
    $key_3f86 = { 68 f4 [2] 5a d6 [2] 5c e3 [2] 72 e3 [2] 4d ff }

  condition:
    any of them
}