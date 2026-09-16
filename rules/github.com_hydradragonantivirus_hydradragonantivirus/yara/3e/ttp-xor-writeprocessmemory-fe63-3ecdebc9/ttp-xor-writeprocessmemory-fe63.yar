rule TTP_XOR_WriteProcessMemory_fe63 {
  strings:
    $key_fe63 = { a9 11 [2] 9b 33 [2] 9d 06 [2] b3 06 [2] 8c 1a }

  condition:
    any of them
}