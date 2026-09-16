rule TTP_XOR_WriteProcessMemory_66d4 {
  strings:
    $key_66d4 = { 31 a6 [2] 03 84 [2] 05 b1 [2] 2b b1 [2] 14 ad }

  condition:
    any of them
}