rule TTP_XOR_WriteProcessMemory_62a9 {
  strings:
    $key_62a9 = { 35 db [2] 07 f9 [2] 01 cc [2] 2f cc [2] 10 d0 }

  condition:
    any of them
}