rule TTP_XOR_WriteProcessMemory_63d5 {
  strings:
    $key_63d5 = { 34 a7 [2] 06 85 [2] 00 b0 [2] 2e b0 [2] 11 ac }

  condition:
    any of them
}