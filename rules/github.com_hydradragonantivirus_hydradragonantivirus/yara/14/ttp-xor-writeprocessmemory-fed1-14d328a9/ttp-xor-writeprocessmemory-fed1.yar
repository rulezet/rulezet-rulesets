rule TTP_XOR_WriteProcessMemory_fed1 {
  strings:
    $key_fed1 = { a9 a3 [2] 9b 81 [2] 9d b4 [2] b3 b4 [2] 8c a8 }

  condition:
    any of them
}