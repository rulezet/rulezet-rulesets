rule TTP_XOR_WriteProcessMemory_fe94 {
  strings:
    $key_fe94 = { a9 e6 [2] 9b c4 [2] 9d f1 [2] b3 f1 [2] 8c ed }

  condition:
    any of them
}