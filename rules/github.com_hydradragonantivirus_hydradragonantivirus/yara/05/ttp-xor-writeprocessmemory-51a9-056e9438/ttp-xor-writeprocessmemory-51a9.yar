rule TTP_XOR_WriteProcessMemory_51a9 {
  strings:
    $key_51a9 = { 06 db [2] 34 f9 [2] 32 cc [2] 1c cc [2] 23 d0 }

  condition:
    any of them
}