rule TTP_XOR_WriteProcessMemory_5d94 {
  strings:
    $key_5d94 = { 0a e6 [2] 38 c4 [2] 3e f1 [2] 10 f1 [2] 2f ed }

  condition:
    any of them
}