rule TTP_XOR_WriteProcessMemory_3297 {
  strings:
    $key_3297 = { 65 e5 [2] 57 c7 [2] 51 f2 [2] 7f f2 [2] 40 ee }

  condition:
    any of them
}