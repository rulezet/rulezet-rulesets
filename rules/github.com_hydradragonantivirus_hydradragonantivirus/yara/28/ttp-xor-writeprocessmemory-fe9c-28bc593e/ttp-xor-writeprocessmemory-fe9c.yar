rule TTP_XOR_WriteProcessMemory_fe9c {
  strings:
    $key_fe9c = { a9 ee [2] 9b cc [2] 9d f9 [2] b3 f9 [2] 8c e5 }

  condition:
    any of them
}