rule TTP_XOR_WriteProcessMemory_2fb0 {
  strings:
    $key_2fb0 = { 78 c2 [2] 4a e0 [2] 4c d5 [2] 62 d5 [2] 5d c9 }

  condition:
    any of them
}