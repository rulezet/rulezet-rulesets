rule TTP_XOR_WriteProcessMemory_59c2 {
  strings:
    $key_59c2 = { 0e b0 [2] 3c 92 [2] 3a a7 [2] 14 a7 [2] 2b bb }

  condition:
    any of them
}