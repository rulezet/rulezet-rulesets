rule TTP_XOR_WriteProcessMemory_7396 {
  strings:
    $key_7396 = { 24 e4 [2] 16 c6 [2] 10 f3 [2] 3e f3 [2] 01 ef }

  condition:
    any of them
}