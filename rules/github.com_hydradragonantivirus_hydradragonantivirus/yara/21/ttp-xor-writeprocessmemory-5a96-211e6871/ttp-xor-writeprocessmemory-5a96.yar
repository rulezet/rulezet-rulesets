rule TTP_XOR_WriteProcessMemory_5a96 {
  strings:
    $key_5a96 = { 0d e4 [2] 3f c6 [2] 39 f3 [2] 17 f3 [2] 28 ef }

  condition:
    any of them
}