rule TTP_XOR_WriteProcessMemory_1791 {
  strings:
    $key_1791 = { 40 e3 [2] 72 c1 [2] 74 f4 [2] 5a f4 [2] 65 e8 }

  condition:
    any of them
}