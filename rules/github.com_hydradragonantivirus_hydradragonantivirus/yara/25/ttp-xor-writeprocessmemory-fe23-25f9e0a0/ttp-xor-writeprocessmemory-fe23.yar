rule TTP_XOR_WriteProcessMemory_fe23 {
  strings:
    $key_fe23 = { a9 51 [2] 9b 73 [2] 9d 46 [2] b3 46 [2] 8c 5a }

  condition:
    any of them
}