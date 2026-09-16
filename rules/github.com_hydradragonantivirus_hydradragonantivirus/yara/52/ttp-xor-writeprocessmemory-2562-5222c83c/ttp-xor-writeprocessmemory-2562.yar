rule TTP_XOR_WriteProcessMemory_2562 {
  strings:
    $key_2562 = { 72 10 [2] 40 32 [2] 46 07 [2] 68 07 [2] 57 1b }

  condition:
    any of them
}