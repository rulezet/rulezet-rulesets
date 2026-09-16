rule TTP_XOR_WriteProcessMemory_77f1 {
  strings:
    $key_77f1 = { 20 83 [2] 12 a1 [2] 14 94 [2] 3a 94 [2] 05 88 }

  condition:
    any of them
}