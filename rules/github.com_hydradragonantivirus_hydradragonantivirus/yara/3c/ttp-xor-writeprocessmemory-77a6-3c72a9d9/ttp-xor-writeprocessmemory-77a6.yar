rule TTP_XOR_WriteProcessMemory_77a6 {
  strings:
    $key_77a6 = { 20 d4 [2] 12 f6 [2] 14 c3 [2] 3a c3 [2] 05 df }

  condition:
    any of them
}