rule TTP_XOR_WriteProcessMemory_3496 {
  strings:
    $key_3496 = { 63 e4 [2] 51 c6 [2] 57 f3 [2] 79 f3 [2] 46 ef }

  condition:
    any of them
}