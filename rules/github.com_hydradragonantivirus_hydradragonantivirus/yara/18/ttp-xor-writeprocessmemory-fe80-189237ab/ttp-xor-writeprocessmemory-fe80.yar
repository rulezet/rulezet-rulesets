rule TTP_XOR_WriteProcessMemory_fe80 {
  strings:
    $key_fe80 = { a9 f2 [2] 9b d0 [2] 9d e5 [2] b3 e5 [2] 8c f9 }

  condition:
    any of them
}