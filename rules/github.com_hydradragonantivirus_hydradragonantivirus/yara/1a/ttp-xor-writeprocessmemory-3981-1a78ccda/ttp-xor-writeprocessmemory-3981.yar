rule TTP_XOR_WriteProcessMemory_3981 {
  strings:
    $key_3981 = { 6e f3 [2] 5c d1 [2] 5a e4 [2] 74 e4 [2] 4b f8 }

  condition:
    any of them
}