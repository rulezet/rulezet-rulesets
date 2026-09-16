rule TTP_XOR_WriteProcessMemory_07c4 {
  strings:
    $key_07c4 = { 50 b6 [2] 62 94 [2] 64 a1 [2] 4a a1 [2] 75 bd }

  condition:
    any of them
}