rule TTP_XOR_WriteProcessMemory_2762 {
  strings:
    $key_2762 = { 70 10 [2] 42 32 [2] 44 07 [2] 6a 07 [2] 55 1b }

  condition:
    any of them
}