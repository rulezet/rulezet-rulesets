rule TTP_XOR_WriteProcessMemory_1797 {
  strings:
    $key_1797 = { 40 e5 [2] 72 c7 [2] 74 f2 [2] 5a f2 [2] 65 ee }

  condition:
    any of them
}