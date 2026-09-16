rule TTP_XOR_WriteProcessMemory_5284 {
  strings:
    $key_5284 = { 05 f6 [2] 37 d4 [2] 31 e1 [2] 1f e1 [2] 20 fd }

  condition:
    any of them
}