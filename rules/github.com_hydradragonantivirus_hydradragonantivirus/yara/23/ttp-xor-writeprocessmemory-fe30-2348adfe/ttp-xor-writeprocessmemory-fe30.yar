rule TTP_XOR_WriteProcessMemory_fe30 {
  strings:
    $key_fe30 = { a9 42 [2] 9b 60 [2] 9d 55 [2] b3 55 [2] 8c 49 }

  condition:
    any of them
}