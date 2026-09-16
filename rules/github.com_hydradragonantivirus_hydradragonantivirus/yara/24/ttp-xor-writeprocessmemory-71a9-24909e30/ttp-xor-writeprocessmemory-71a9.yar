rule TTP_XOR_WriteProcessMemory_71a9 {
  strings:
    $key_71a9 = { 26 db [2] 14 f9 [2] 12 cc [2] 3c cc [2] 03 d0 }

  condition:
    any of them
}