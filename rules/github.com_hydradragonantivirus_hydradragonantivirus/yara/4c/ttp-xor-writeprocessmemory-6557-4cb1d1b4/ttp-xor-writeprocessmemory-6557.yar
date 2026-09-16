rule TTP_XOR_WriteProcessMemory_6557 {
  strings:
    $key_6557 = { 32 25 [2] 00 07 [2] 06 32 [2] 28 32 [2] 17 2e }

  condition:
    any of them
}