rule TTP_XOR_WriteProcessMemory_59c1 {
  strings:
    $key_59c1 = { 0e b3 [2] 3c 91 [2] 3a a4 [2] 14 a4 [2] 2b b8 }

  condition:
    any of them
}