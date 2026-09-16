rule TTP_XOR_WriteProcessMemory_4cc1 {
  strings:
    $key_4cc1 = { 1b b3 [2] 29 91 [2] 2f a4 [2] 01 a4 [2] 3e b8 }

  condition:
    any of them
}