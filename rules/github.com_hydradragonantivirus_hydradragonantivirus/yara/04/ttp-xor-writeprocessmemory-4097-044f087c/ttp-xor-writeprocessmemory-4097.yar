rule TTP_XOR_WriteProcessMemory_4097 {
  strings:
    $key_4097 = { 17 e5 [2] 25 c7 [2] 23 f2 [2] 0d f2 [2] 32 ee }

  condition:
    any of them
}