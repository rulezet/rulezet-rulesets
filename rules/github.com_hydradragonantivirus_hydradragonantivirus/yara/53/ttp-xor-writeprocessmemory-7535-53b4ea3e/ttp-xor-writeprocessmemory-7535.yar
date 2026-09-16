rule TTP_XOR_WriteProcessMemory_7535 {
  strings:
    $key_7535 = { 22 47 [2] 10 65 [2] 16 50 [2] 38 50 [2] 07 4c }

  condition:
    any of them
}