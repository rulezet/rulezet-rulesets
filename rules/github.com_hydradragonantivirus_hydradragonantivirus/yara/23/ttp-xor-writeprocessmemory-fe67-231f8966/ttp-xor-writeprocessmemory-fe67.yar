rule TTP_XOR_WriteProcessMemory_fe67 {
  strings:
    $key_fe67 = { a9 15 [2] 9b 37 [2] 9d 02 [2] b3 02 [2] 8c 1e }

  condition:
    any of them
}