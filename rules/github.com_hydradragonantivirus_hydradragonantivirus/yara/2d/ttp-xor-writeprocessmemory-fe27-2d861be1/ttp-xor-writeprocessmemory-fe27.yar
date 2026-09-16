rule TTP_XOR_WriteProcessMemory_fe27 {
  strings:
    $key_fe27 = { a9 55 [2] 9b 77 [2] 9d 42 [2] b3 42 [2] 8c 5e }

  condition:
    any of them
}