rule TTP_XOR_WriteProcessMemory_4d80 {
  strings:
    $key_4d80 = { 1a f2 [2] 28 d0 [2] 2e e5 [2] 00 e5 [2] 3f f9 }

  condition:
    any of them
}