rule TTP_XOR_WriteProcessMemory_6280 {
  strings:
    $key_6280 = { 35 f2 [2] 07 d0 [2] 01 e5 [2] 2f e5 [2] 10 f9 }

  condition:
    any of them
}