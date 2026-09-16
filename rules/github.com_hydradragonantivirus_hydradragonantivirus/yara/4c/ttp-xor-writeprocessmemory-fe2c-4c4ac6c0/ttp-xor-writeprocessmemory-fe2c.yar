rule TTP_XOR_WriteProcessMemory_fe2c {
  strings:
    $key_fe2c = { a9 5e [2] 9b 7c [2] 9d 49 [2] b3 49 [2] 8c 55 }

  condition:
    any of them
}