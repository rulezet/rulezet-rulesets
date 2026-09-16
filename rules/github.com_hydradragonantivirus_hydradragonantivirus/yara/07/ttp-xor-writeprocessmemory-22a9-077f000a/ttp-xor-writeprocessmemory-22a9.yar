rule TTP_XOR_WriteProcessMemory_22a9 {
  strings:
    $key_22a9 = { 75 db [2] 47 f9 [2] 41 cc [2] 6f cc [2] 50 d0 }

  condition:
    any of them
}