rule TTP_XOR_WriteProcessMemory_1dd6 {
  strings:
    $key_1dd6 = { 4a a4 [2] 78 86 [2] 7e b3 [2] 50 b3 [2] 6f af }

  condition:
    any of them
}