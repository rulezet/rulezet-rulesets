rule TTP_XOR_WriteProcessMemory_fe55 {
  strings:
    $key_fe55 = { a9 27 [2] 9b 05 [2] 9d 30 [2] b3 30 [2] 8c 2c }

  condition:
    any of them
}