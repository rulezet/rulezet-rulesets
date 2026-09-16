rule TTP_XOR_WriteProcessMemory_49c1 {
  strings:
    $key_49c1 = { 1e b3 [2] 2c 91 [2] 2a a4 [2] 04 a4 [2] 3b b8 }

  condition:
    any of them
}