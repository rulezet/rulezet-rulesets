rule TTP_XOR_WriteProcessMemory_59c3 {
  strings:
    $key_59c3 = { 0e b1 [2] 3c 93 [2] 3a a6 [2] 14 a6 [2] 2b ba }

  condition:
    any of them
}