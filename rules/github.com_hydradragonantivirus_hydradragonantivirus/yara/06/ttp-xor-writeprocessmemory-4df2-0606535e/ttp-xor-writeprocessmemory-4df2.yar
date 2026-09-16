rule TTP_XOR_WriteProcessMemory_4df2 {
  strings:
    $key_4df2 = { 1a 80 [2] 28 a2 [2] 2e 97 [2] 00 97 [2] 3f 8b }

  condition:
    any of them
}