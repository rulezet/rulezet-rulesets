rule TTP_XOR_WriteProcessMemory_0684 {
  strings:
    $key_0684 = { 51 f6 [2] 63 d4 [2] 65 e1 [2] 4b e1 [2] 74 fd }

  condition:
    any of them
}