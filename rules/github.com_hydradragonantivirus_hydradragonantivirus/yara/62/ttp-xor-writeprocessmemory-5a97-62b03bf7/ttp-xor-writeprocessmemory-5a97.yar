rule TTP_XOR_WriteProcessMemory_5a97 {
  strings:
    $key_5a97 = { 0d e5 [2] 3f c7 [2] 39 f2 [2] 17 f2 [2] 28 ee }

  condition:
    any of them
}