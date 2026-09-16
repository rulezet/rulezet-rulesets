rule TTP_XOR_WriteProcessMemory_6d80 {
  strings:
    $key_6d80 = { 3a f2 [2] 08 d0 [2] 0e e5 [2] 20 e5 [2] 1f f9 }

  condition:
    any of them
}