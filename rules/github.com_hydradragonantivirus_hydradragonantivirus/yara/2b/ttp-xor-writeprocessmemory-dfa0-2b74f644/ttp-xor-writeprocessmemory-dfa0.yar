rule TTP_XOR_WriteProcessMemory_dfa0 {
  strings:
    $key_dfa0 = { 88 d2 [2] ba f0 [2] bc c5 [2] 92 c5 [2] ad d9 }

  condition:
    any of them
}