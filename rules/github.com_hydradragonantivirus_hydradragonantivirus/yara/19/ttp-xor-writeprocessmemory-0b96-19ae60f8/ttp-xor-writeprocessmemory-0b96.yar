rule TTP_XOR_WriteProcessMemory_0b96 {
  strings:
    $key_0b96 = { 5c e4 [2] 6e c6 [2] 68 f3 [2] 46 f3 [2] 79 ef }

  condition:
    any of them
}