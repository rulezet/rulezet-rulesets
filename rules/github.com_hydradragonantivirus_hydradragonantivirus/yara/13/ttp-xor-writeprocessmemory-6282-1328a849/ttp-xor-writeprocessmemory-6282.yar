rule TTP_XOR_WriteProcessMemory_6282 {
  strings:
    $key_6282 = { 35 f0 [2] 07 d2 [2] 01 e7 [2] 2f e7 [2] 10 fb }

  condition:
    any of them
}