rule TTP_XOR_WriteProcessMemory_14a9 {
  strings:
    $key_14a9 = { 43 db [2] 71 f9 [2] 77 cc [2] 59 cc [2] 66 d0 }

  condition:
    any of them
}