rule TTP_XOR_WriteProcessMemory_dfa9 {
  strings:
    $key_dfa9 = { 88 db [2] ba f9 [2] bc cc [2] 92 cc [2] ad d0 }

  condition:
    any of them
}