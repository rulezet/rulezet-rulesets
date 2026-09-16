rule TTP_XOR_WriteProcessMemory_25c4 {
  strings:
    $key_25c4 = { 72 b6 [2] 40 94 [2] 46 a1 [2] 68 a1 [2] 57 bd }

  condition:
    any of them
}