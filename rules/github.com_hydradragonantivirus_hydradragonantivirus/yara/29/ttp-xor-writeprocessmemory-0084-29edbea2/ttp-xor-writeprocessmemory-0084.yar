rule TTP_XOR_WriteProcessMemory_0084 {
  strings:
    $key_0084 = { 57 f6 [2] 65 d4 [2] 63 e1 [2] 4d e1 [2] 72 fd }

  condition:
    any of them
}