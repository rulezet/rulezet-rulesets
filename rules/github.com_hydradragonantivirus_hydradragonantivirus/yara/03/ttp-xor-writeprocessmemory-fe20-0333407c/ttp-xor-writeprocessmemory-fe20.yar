rule TTP_XOR_WriteProcessMemory_fe20 {
  strings:
    $key_fe20 = { a9 52 [2] 9b 70 [2] 9d 45 [2] b3 45 [2] 8c 59 }

  condition:
    any of them
}