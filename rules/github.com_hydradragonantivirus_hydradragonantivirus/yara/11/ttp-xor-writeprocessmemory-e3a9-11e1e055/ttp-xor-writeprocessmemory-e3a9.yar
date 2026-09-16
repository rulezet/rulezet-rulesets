rule TTP_XOR_WriteProcessMemory_e3a9 {
  strings:
    $key_e3a9 = { b4 db [2] 86 f9 [2] 80 cc [2] ae cc [2] 91 d0 }

  condition:
    any of them
}