rule TTP_XOR_WriteProcessMemory_6d82 {
  strings:
    $key_6d82 = { 3a f0 [2] 08 d2 [2] 0e e7 [2] 20 e7 [2] 1f fb }

  condition:
    any of them
}