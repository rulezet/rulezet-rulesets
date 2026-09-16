rule TTP_XOR_WriteProcessMemory_0d96 {
  strings:
    $key_0d96 = { 5a e4 [2] 68 c6 [2] 6e f3 [2] 40 f3 [2] 7f ef }

  condition:
    any of them
}