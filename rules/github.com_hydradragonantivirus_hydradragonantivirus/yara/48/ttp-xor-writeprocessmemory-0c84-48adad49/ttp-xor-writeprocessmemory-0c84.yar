rule TTP_XOR_WriteProcessMemory_0c84 {
  strings:
    $key_0c84 = { 5b f6 [2] 69 d4 [2] 6f e1 [2] 41 e1 [2] 7e fd }

  condition:
    any of them
}