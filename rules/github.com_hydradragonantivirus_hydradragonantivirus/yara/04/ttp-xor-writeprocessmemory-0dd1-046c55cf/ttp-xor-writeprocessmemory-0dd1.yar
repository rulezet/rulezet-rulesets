rule TTP_XOR_WriteProcessMemory_0dd1 {
  strings:
    $key_0dd1 = { 5a a3 [2] 68 81 [2] 6e b4 [2] 40 b4 [2] 7f a8 }

  condition:
    any of them
}