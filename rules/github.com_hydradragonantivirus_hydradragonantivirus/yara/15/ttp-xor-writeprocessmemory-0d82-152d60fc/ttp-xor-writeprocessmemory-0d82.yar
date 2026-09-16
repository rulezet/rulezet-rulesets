rule TTP_XOR_WriteProcessMemory_0d82 {
  strings:
    $key_0d82 = { 5a f0 [2] 68 d2 [2] 6e e7 [2] 40 e7 [2] 7f fb }

  condition:
    any of them
}