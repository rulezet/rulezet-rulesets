rule TTP_XOR_WriteProcessMemory_5df3 {
  strings:
    $key_5df3 = { 0a 81 [2] 38 a3 [2] 3e 96 [2] 10 96 [2] 2f 8a }

  condition:
    any of them
}