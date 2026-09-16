rule TTP_XOR_WriteProcessMemory_fe34 {
  strings:
    $key_fe34 = { a9 46 [2] 9b 64 [2] 9d 51 [2] b3 51 [2] 8c 4d }

  condition:
    any of them
}