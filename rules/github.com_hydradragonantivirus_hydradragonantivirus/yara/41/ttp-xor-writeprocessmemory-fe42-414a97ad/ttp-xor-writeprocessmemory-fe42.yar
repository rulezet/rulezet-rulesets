rule TTP_XOR_WriteProcessMemory_fe42 {
  strings:
    $key_fe42 = { a9 30 [2] 9b 12 [2] 9d 27 [2] b3 27 [2] 8c 3b }

  condition:
    any of them
}