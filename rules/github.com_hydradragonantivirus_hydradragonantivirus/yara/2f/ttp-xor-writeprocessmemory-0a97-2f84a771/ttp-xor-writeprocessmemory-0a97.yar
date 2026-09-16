rule TTP_XOR_WriteProcessMemory_0a97 {
  strings:
    $key_0a97 = { 5d e5 [2] 6f c7 [2] 69 f2 [2] 47 f2 [2] 78 ee }

  condition:
    any of them
}