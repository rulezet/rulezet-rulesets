rule TTP_XOR_WriteProcessMemory_2d90 {
  strings:
    $key_2d90 = { 7a e2 [2] 48 c0 [2] 4e f5 [2] 60 f5 [2] 5f e9 }

  condition:
    any of them
}