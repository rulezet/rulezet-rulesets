rule TTP_XOR_WriteProcessMemory_628b {
  strings:
    $key_628b = { 35 f9 [2] 07 db [2] 01 ee [2] 2f ee [2] 10 f2 }

  condition:
    any of them
}