rule TTP_XOR_WriteProcessMemory_0980 {
  strings:
    $key_0980 = { 5e f2 [2] 6c d0 [2] 6a e5 [2] 44 e5 [2] 7b f9 }

  condition:
    any of them
}