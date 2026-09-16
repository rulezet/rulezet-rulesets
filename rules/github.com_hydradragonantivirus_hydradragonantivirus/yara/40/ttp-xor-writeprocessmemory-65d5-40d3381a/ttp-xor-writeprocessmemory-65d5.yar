rule TTP_XOR_WriteProcessMemory_65d5 {
  strings:
    $key_65d5 = { 32 a7 [2] 00 85 [2] 06 b0 [2] 28 b0 [2] 17 ac }

  condition:
    any of them
}