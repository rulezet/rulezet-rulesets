rule TTP_XOR_WriteProcessMemory_4dd6 {
  strings:
    $key_4dd6 = { 1a a4 [2] 28 86 [2] 2e b3 [2] 00 b3 [2] 3f af }

  condition:
    any of them
}