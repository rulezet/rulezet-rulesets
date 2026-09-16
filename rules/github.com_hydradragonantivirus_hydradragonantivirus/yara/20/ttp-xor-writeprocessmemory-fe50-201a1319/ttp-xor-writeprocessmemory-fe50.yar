rule TTP_XOR_WriteProcessMemory_fe50 {
  strings:
    $key_fe50 = { a9 22 [2] 9b 00 [2] 9d 35 [2] b3 35 [2] 8c 29 }

  condition:
    any of them
}