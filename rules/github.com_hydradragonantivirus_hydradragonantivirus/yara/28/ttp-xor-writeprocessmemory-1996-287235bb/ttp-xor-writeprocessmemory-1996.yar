rule TTP_XOR_WriteProcessMemory_1996 {
  strings:
    $key_1996 = { 4e e4 [2] 7c c6 [2] 7a f3 [2] 54 f3 [2] 6b ef }

  condition:
    any of them
}