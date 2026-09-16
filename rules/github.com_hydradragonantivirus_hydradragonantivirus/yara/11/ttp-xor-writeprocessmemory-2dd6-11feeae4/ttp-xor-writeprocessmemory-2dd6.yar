rule TTP_XOR_WriteProcessMemory_2dd6 {
  strings:
    $key_2dd6 = { 7a a4 [2] 48 86 [2] 4e b3 [2] 60 b3 [2] 5f af }

  condition:
    any of them
}