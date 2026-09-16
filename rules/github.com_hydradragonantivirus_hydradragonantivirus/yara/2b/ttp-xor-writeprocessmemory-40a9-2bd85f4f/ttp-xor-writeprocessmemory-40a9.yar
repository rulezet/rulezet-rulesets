rule TTP_XOR_WriteProcessMemory_40a9 {
  strings:
    $key_40a9 = { 17 db [2] 25 f9 [2] 23 cc [2] 0d cc [2] 32 d0 }

  condition:
    any of them
}