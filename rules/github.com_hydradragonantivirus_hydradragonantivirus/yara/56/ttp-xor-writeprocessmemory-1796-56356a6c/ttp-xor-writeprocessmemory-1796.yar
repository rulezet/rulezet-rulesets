rule TTP_XOR_WriteProcessMemory_1796 {
  strings:
    $key_1796 = { 40 e4 [2] 72 c6 [2] 74 f3 [2] 5a f3 [2] 65 ef }

  condition:
    any of them
}