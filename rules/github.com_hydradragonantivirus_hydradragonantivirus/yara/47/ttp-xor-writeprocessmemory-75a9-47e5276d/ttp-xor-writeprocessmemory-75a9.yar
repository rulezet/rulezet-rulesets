rule TTP_XOR_WriteProcessMemory_75a9 {
  strings:
    $key_75a9 = { 22 db [2] 10 f9 [2] 16 cc [2] 38 cc [2] 07 d0 }

  condition:
    any of them
}