rule TTP_XOR_WriteProcessMemory_6dd6 {
  strings:
    $key_6dd6 = { 3a a4 [2] 08 86 [2] 0e b3 [2] 20 b3 [2] 1f af }

  condition:
    any of them
}