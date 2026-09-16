rule TTP_XOR_WriteProcessMemory_5c84 {
  strings:
    $key_5c84 = { 0b f6 [2] 39 d4 [2] 3f e1 [2] 11 e1 [2] 2e fd }

  condition:
    any of them
}