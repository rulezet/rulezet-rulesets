rule TTP_XOR_WriteProcessMemory_63f1 {
  strings:
    $key_63f1 = { 34 83 [2] 06 a1 [2] 00 94 [2] 2e 94 [2] 11 88 }

  condition:
    any of them
}