rule TTP_XOR_WriteProcessMemory_2297 {
  strings:
    $key_2297 = { 75 e5 [2] 47 c7 [2] 41 f2 [2] 6f f2 [2] 50 ee }

  condition:
    any of them
}