rule TTP_XOR_WriteProcessMemory_73c4 {
  strings:
    $key_73c4 = { 24 b6 [2] 16 94 [2] 10 a1 [2] 3e a1 [2] 01 bd }

  condition:
    any of them
}