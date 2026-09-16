rule TTP_XOR_WriteProcessMemory_5462 {
  strings:
    $key_5462 = { 03 10 [2] 31 32 [2] 37 07 [2] 19 07 [2] 26 1b }

  condition:
    any of them
}