rule TTP_XOR_WriteProcessMemory_0996 {
  strings:
    $key_0996 = { 5e e4 [2] 6c c6 [2] 6a f3 [2] 44 f3 [2] 7b ef }

  condition:
    any of them
}