rule TTP_XOR_WriteProcessMemory_59c5 {
  strings:
    $key_59c5 = { 0e b7 [2] 3c 95 [2] 3a a0 [2] 14 a0 [2] 2b bc }

  condition:
    any of them
}