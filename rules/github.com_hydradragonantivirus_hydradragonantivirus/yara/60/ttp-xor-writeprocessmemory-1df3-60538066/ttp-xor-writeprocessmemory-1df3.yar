rule TTP_XOR_WriteProcessMemory_1df3 {
  strings:
    $key_1df3 = { 4a 81 [2] 78 a3 [2] 7e 96 [2] 50 96 [2] 6f 8a }

  condition:
    any of them
}