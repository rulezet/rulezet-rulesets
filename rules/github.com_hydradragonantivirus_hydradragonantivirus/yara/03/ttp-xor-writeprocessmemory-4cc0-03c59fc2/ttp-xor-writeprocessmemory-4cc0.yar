rule TTP_XOR_WriteProcessMemory_4cc0 {
  strings:
    $key_4cc0 = { 1b b2 [2] 29 90 [2] 2f a5 [2] 01 a5 [2] 3e b9 }

  condition:
    any of them
}