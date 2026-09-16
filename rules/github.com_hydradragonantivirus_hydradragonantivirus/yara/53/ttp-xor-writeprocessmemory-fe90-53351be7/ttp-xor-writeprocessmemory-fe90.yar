rule TTP_XOR_WriteProcessMemory_fe90 {
  strings:
    $key_fe90 = { a9 e2 [2] 9b c0 [2] 9d f5 [2] b3 f5 [2] 8c e9 }

  condition:
    any of them
}