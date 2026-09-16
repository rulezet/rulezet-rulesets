rule TTP_XOR_WriteProcessMemory_6d84 {
  strings:
    $key_6d84 = { 3a f6 [2] 08 d4 [2] 0e e1 [2] 20 e1 [2] 1f fd }

  condition:
    any of them
}