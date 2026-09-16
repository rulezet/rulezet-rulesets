rule TTP_XOR_WriteProcessMemory_0d94 {
  strings:
    $key_0d94 = { 5a e6 [2] 68 c4 [2] 6e f1 [2] 40 f1 [2] 7f ed }

  condition:
    any of them
}