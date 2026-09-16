rule TTP_XOR_WriteProcessMemory_5986 {
  strings:
    $key_5986 = { 0e f4 [2] 3c d6 [2] 3a e3 [2] 14 e3 [2] 2b ff }

  condition:
    any of them
}