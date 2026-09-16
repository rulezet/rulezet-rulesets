rule TTP_XOR_WriteProcessMemory_fe07 {
  strings:
    $key_fe07 = { a9 75 [2] 9b 57 [2] 9d 62 [2] b3 62 [2] 8c 7e }

  condition:
    any of them
}