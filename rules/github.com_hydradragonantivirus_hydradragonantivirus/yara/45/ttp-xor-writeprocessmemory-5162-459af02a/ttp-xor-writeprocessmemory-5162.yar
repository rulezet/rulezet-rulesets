rule TTP_XOR_WriteProcessMemory_5162 {
  strings:
    $key_5162 = { 06 10 [2] 34 32 [2] 32 07 [2] 1c 07 [2] 23 1b }

  condition:
    any of them
}