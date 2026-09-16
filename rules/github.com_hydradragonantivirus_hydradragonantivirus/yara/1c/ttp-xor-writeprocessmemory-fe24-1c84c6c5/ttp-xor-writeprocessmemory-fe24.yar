rule TTP_XOR_WriteProcessMemory_fe24 {
  strings:
    $key_fe24 = { a9 56 [2] 9b 74 [2] 9d 41 [2] b3 41 [2] 8c 5d }

  condition:
    any of them
}