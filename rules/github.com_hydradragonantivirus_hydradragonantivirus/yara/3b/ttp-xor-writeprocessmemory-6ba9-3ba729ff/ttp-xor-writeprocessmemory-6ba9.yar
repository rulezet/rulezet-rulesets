rule TTP_XOR_WriteProcessMemory_6ba9 {
  strings:
    $key_6ba9 = { 3c db [2] 0e f9 [2] 08 cc [2] 26 cc [2] 19 d0 }

  condition:
    any of them
}