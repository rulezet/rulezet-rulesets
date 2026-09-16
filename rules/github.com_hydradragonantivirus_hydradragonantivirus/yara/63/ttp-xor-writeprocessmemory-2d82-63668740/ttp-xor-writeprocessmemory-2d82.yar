rule TTP_XOR_WriteProcessMemory_2d82 {
  strings:
    $key_2d82 = { 7a f0 [2] 48 d2 [2] 4e e7 [2] 60 e7 [2] 5f fb }

  condition:
    any of them
}