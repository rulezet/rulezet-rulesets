rule TTP_XOR_WriteProcessMemory_2fb1 {
  strings:
    $key_2fb1 = { 78 c3 [2] 4a e1 [2] 4c d4 [2] 62 d4 [2] 5d c8 }

  condition:
    any of them
}