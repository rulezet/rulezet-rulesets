rule TTP_XOR_WriteProcessMemory_1d80 {
  strings:
    $key_1d80 = { 4a f2 [2] 78 d0 [2] 7e e5 [2] 50 e5 [2] 6f f9 }

  condition:
    any of them
}