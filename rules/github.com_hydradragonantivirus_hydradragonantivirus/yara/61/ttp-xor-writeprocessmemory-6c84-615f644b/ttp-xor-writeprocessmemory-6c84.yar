rule TTP_XOR_WriteProcessMemory_6c84 {
  strings:
    $key_6c84 = { 3b f6 [2] 09 d4 [2] 0f e1 [2] 21 e1 [2] 1e fd }

  condition:
    any of them
}