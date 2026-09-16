rule TTP_XOR_WriteProcessMemory_7297 {
  strings:
    $key_7297 = { 25 e5 [2] 17 c7 [2] 11 f2 [2] 3f f2 [2] 00 ee }

  condition:
    any of them
}