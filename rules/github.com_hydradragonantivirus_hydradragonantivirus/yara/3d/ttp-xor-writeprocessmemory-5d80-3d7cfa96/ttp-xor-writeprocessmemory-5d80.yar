rule TTP_XOR_WriteProcessMemory_5d80 {
  strings:
    $key_5d80 = { 0a f2 [2] 38 d0 [2] 3e e5 [2] 10 e5 [2] 2f f9 }

  condition:
    any of them
}