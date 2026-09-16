rule TTP_XOR_WriteProcessMemory_2996 {
  strings:
    $key_2996 = { 7e e4 [2] 4c c6 [2] 4a f3 [2] 64 f3 [2] 5b ef }

  condition:
    any of them
}