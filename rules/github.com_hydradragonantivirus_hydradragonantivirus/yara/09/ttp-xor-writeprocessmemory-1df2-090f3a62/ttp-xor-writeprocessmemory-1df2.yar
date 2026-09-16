rule TTP_XOR_WriteProcessMemory_1df2 {
  strings:
    $key_1df2 = { 4a 80 [2] 78 a2 [2] 7e 97 [2] 50 97 [2] 6f 8b }

  condition:
    any of them
}