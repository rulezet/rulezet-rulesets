rule TTP_XOR_WriteProcessMemory_fed2 {
  strings:
    $key_fed2 = { a9 a0 [2] 9b 82 [2] 9d b7 [2] b3 b7 [2] 8c ab }

  condition:
    any of them
}