rule TTP_XOR_WriteProcessMemory_16a9 {
  strings:
    $key_16a9 = { 41 db [2] 73 f9 [2] 75 cc [2] 5b cc [2] 64 d0 }

  condition:
    any of them
}