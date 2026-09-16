rule TTP_XOR_WriteProcessMemory_6380 {
  strings:
    $key_6380 = { 34 f2 [2] 06 d0 [2] 00 e5 [2] 2e e5 [2] 11 f9 }

  condition:
    any of them
}