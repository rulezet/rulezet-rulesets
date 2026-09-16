rule TTP_XOR_WriteProcessMemory_5797 {
  strings:
    $key_5797 = { 00 e5 [2] 32 c7 [2] 34 f2 [2] 1a f2 [2] 25 ee }

  condition:
    any of them
}