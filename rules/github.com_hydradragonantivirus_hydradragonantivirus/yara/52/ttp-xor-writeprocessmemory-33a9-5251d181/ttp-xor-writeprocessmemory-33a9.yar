rule TTP_XOR_WriteProcessMemory_33a9 {
  strings:
    $key_33a9 = { 64 db [2] 56 f9 [2] 50 cc [2] 7e cc [2] 41 d0 }

  condition:
    any of them
}