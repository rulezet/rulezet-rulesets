rule TTP_XOR_WriteProcessMemory_0a96 {
  strings:
    $key_0a96 = { 5d e4 [2] 6f c6 [2] 69 f3 [2] 47 f3 [2] 78 ef }

  condition:
    any of them
}