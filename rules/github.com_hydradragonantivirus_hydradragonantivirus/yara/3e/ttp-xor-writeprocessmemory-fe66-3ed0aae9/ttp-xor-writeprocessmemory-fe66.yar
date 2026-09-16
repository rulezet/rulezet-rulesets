rule TTP_XOR_WriteProcessMemory_fe66 {
  strings:
    $key_fe66 = { a9 14 [2] 9b 36 [2] 9d 03 [2] b3 03 [2] 8c 1f }

  condition:
    any of them
}