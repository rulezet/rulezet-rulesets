rule TTP_XOR_WriteProcessMemory_1296 {
  strings:
    $key_1296 = { 45 e4 [2] 77 c6 [2] 71 f3 [2] 5f f3 [2] 60 ef }

  condition:
    any of them
}