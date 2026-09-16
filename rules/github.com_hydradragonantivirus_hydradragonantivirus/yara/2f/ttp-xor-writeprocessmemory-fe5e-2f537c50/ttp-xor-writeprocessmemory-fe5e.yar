rule TTP_XOR_WriteProcessMemory_fe5e {
  strings:
    $key_fe5e = { a9 2c [2] 9b 0e [2] 9d 3b [2] b3 3b [2] 8c 27 }

  condition:
    any of them
}