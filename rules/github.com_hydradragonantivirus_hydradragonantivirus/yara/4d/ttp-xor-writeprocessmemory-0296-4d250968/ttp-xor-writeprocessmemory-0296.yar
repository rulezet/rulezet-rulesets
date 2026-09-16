rule TTP_XOR_WriteProcessMemory_0296 {
  strings:
    $key_0296 = { 55 e4 [2] 67 c6 [2] 61 f3 [2] 4f f3 [2] 70 ef }

  condition:
    any of them
}