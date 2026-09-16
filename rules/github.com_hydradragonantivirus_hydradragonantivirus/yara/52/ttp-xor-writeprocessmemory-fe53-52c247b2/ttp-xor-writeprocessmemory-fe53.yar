rule TTP_XOR_WriteProcessMemory_fe53 {
  strings:
    $key_fe53 = { a9 21 [2] 9b 03 [2] 9d 36 [2] b3 36 [2] 8c 2a }

  condition:
    any of them
}