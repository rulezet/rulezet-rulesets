rule TTP_XOR_WriteProcessMemory_1980 {
  strings:
    $key_1980 = { 4e f2 [2] 7c d0 [2] 7a e5 [2] 54 e5 [2] 6b f9 }

  condition:
    any of them
}