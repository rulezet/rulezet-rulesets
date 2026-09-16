rule TTP_XOR_WriteProcessMemory_2d80 {
  strings:
    $key_2d80 = { 7a f2 [2] 48 d0 [2] 4e e5 [2] 60 e5 [2] 5f f9 }

  condition:
    any of them
}