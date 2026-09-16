rule TTP_XOR_WriteProcessMemory_5df2 {
  strings:
    $key_5df2 = { 0a 80 [2] 38 a2 [2] 3e 97 [2] 10 97 [2] 2f 8b }

  condition:
    any of them
}