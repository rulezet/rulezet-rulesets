rule TTP_XOR_WriteProcessMemory_fe96 {
  strings:
    $key_fe96 = { a9 e4 [2] 9b c6 [2] 9d f3 [2] b3 f3 [2] 8c ef }

  condition:
    any of them
}