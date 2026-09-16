rule TTP_XOR_WriteProcessMemory_5717 {
  strings:
    $key_5717 = { 00 65 [2] 32 47 [2] 34 72 [2] 1a 72 [2] 25 6e }

  condition:
    any of them
}