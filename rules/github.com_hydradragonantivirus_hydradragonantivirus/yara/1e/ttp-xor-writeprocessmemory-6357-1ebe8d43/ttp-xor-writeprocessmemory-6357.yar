rule TTP_XOR_WriteProcessMemory_6357 {
  strings:
    $key_6357 = { 34 25 [2] 06 07 [2] 00 32 [2] 2e 32 [2] 11 2e }

  condition:
    any of them
}