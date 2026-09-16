rule TTP_XOR_WriteProcessMemory_fed0 {
  strings:
    $key_fed0 = { a9 a2 [2] 9b 80 [2] 9d b5 [2] b3 b5 [2] 8c a9 }

  condition:
    any of them
}