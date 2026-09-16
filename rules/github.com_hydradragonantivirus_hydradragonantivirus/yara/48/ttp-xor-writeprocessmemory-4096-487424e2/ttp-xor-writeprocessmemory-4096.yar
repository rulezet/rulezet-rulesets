rule TTP_XOR_WriteProcessMemory_4096 {
  strings:
    $key_4096 = { 17 e4 [2] 25 c6 [2] 23 f3 [2] 0d f3 [2] 32 ef }

  condition:
    any of them
}