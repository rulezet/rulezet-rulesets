rule TTP_XOR_WriteProcessMemory_2d94 {
  strings:
    $key_2d94 = { 7a e6 [2] 48 c4 [2] 4e f1 [2] 60 f1 [2] 5f ed }

  condition:
    any of them
}