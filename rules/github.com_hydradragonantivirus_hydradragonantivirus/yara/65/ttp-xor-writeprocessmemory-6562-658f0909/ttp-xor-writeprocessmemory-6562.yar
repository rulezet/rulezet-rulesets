rule TTP_XOR_WriteProcessMemory_6562 {
  strings:
    $key_6562 = { 32 10 [2] 00 32 [2] 06 07 [2] 28 07 [2] 17 1b }

  condition:
    any of them
}