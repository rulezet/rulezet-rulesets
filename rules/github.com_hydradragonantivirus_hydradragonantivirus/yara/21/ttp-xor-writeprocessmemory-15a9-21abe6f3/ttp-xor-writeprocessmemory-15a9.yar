rule TTP_XOR_WriteProcessMemory_15a9 {
  strings:
    $key_15a9 = { 42 db [2] 70 f9 [2] 76 cc [2] 58 cc [2] 67 d0 }

  condition:
    any of them
}