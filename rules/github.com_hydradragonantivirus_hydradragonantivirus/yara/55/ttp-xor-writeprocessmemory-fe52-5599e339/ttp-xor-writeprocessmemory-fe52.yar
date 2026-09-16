rule TTP_XOR_WriteProcessMemory_fe52 {
  strings:
    $key_fe52 = { a9 20 [2] 9b 02 [2] 9d 37 [2] b3 37 [2] 8c 2b }

  condition:
    any of them
}