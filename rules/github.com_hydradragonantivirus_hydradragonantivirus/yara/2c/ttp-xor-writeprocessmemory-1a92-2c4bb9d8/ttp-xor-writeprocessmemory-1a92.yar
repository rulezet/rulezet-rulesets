rule TTP_XOR_WriteProcessMemory_1a92 {
  strings:
    $key_1a92 = { 4d e0 [2] 7f c2 [2] 79 f7 [2] 57 f7 [2] 68 eb }

  condition:
    any of them
}