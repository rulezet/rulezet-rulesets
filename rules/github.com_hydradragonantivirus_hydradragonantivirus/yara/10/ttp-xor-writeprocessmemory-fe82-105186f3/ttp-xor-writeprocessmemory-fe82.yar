rule TTP_XOR_WriteProcessMemory_fe82 {
  strings:
    $key_fe82 = { a9 f0 [2] 9b d2 [2] 9d e7 [2] b3 e7 [2] 8c fb }

  condition:
    any of them
}