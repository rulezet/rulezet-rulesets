rule TTP_XOR_WriteProcessMemory_12a9 {
  strings:
    $key_12a9 = { 45 db [2] 77 f9 [2] 71 cc [2] 5f cc [2] 60 d0 }

  condition:
    any of them
}