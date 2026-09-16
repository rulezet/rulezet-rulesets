rule TTP_XOR_WriteProcessMemory_6981 {
  strings:
    $key_6981 = { 3e f3 [2] 0c d1 [2] 0a e4 [2] 24 e4 [2] 1b f8 }

  condition:
    any of them
}