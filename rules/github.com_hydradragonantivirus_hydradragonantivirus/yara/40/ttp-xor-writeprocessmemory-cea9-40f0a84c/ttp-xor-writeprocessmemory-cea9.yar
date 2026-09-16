rule TTP_XOR_WriteProcessMemory_cea9 {
  strings:
    $key_cea9 = { 99 db [2] ab f9 [2] ad cc [2] 83 cc [2] bc d0 }

  condition:
    any of them
}