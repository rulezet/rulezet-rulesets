rule TTP_XOR_WriteProcessMemory_74a6 {
  strings:
    $key_74a6 = { 23 d4 [2] 11 f6 [2] 17 c3 [2] 39 c3 [2] 06 df }

  condition:
    any of them
}