rule TTP_XOR_WriteProcessMemory_46a9 {
  strings:
    $key_46a9 = { 11 db [2] 23 f9 [2] 25 cc [2] 0b cc [2] 34 d0 }

  condition:
    any of them
}