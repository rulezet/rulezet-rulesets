rule TTP_XOR_WriteProcessMemory_0986 {
  strings:
    $key_0986 = { 5e f4 [2] 6c d6 [2] 6a e3 [2] 44 e3 [2] 7b ff }

  condition:
    any of them
}