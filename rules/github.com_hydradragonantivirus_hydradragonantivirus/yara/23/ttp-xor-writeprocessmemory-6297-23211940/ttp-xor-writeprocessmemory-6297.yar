rule TTP_XOR_WriteProcessMemory_6297 {
  strings:
    $key_6297 = { 35 e5 [2] 07 c7 [2] 01 f2 [2] 2f f2 [2] 10 ee }

  condition:
    any of them
}