rule TTP_XOR_WriteProcessMemory_fe35 {
  strings:
    $key_fe35 = { a9 47 [2] 9b 65 [2] 9d 50 [2] b3 50 [2] 8c 4c }

  condition:
    any of them
}