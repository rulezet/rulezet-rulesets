rule TTP_XOR_WriteProcessMemory_0d81 {
  strings:
    $key_0d81 = { 5a f3 [2] 68 d1 [2] 6e e4 [2] 40 e4 [2] 7f f8 }

  condition:
    any of them
}