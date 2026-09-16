rule TTP_XOR_WriteProcessMemory_0dd6 {
  strings:
    $key_0dd6 = { 5a a4 [2] 68 86 [2] 6e b3 [2] 40 b3 [2] 7f af }

  condition:
    any of them
}