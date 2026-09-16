rule TTP_XOR_WriteProcessMemory_2a97 {
  strings:
    $key_2a97 = { 7d e5 [2] 4f c7 [2] 49 f2 [2] 67 f2 [2] 58 ee }

  condition:
    any of them
}