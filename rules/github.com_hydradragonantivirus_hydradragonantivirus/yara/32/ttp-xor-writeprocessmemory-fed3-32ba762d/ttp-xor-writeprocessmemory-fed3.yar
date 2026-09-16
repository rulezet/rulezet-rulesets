rule TTP_XOR_WriteProcessMemory_fed3 {
  strings:
    $key_fed3 = { a9 a1 [2] 9b 83 [2] 9d b6 [2] b3 b6 [2] 8c aa }

  condition:
    any of them
}