rule TTP_XOR_WriteProcessMemory_fe48 {
  strings:
    $key_fe48 = { a9 3a [2] 9b 18 [2] 9d 2d [2] b3 2d [2] 8c 31 }

  condition:
    any of them
}