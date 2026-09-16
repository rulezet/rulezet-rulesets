rule TTP_XOR_WriteProcessMemory_fe21 {
  strings:
    $key_fe21 = { a9 53 [2] 9b 71 [2] 9d 44 [2] b3 44 [2] 8c 58 }

  condition:
    any of them
}