rule TTP_XOR_WriteProcessMemory_1297 {
  strings:
    $key_1297 = { 45 e5 [2] 77 c7 [2] 71 f2 [2] 5f f2 [2] 60 ee }

  condition:
    any of them
}