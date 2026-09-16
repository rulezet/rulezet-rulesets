rule TTP_XOR_WriteProcessMemory_fe16 {
  strings:
    $key_fe16 = { a9 64 [2] 9b 46 [2] 9d 73 [2] b3 73 [2] 8c 6f }

  condition:
    any of them
}