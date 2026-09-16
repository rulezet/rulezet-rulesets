rule TTP_XOR_WriteProcessMemory_7a96 {
  strings:
    $key_7a96 = { 2d e4 [2] 1f c6 [2] 19 f3 [2] 37 f3 [2] 08 ef }

  condition:
    any of them
}