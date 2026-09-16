rule TTP_XOR_WriteProcessMemory_0d84 {
  strings:
    $key_0d84 = { 5a f6 [2] 68 d4 [2] 6e e1 [2] 40 e1 [2] 7f fd }

  condition:
    any of them
}