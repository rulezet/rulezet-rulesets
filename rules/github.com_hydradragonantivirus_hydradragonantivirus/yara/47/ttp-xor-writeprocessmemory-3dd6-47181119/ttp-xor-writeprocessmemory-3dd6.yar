rule TTP_XOR_WriteProcessMemory_3dd6 {
  strings:
    $key_3dd6 = { 6a a4 [2] 58 86 [2] 5e b3 [2] 70 b3 [2] 4f af }

  condition:
    any of them
}