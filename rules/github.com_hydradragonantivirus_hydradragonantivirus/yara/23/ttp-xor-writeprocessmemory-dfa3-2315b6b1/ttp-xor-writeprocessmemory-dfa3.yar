rule TTP_XOR_WriteProcessMemory_dfa3 {
  strings:
    $key_dfa3 = { 88 d1 [2] ba f3 [2] bc c6 [2] 92 c6 [2] ad da }

  condition:
    any of them
}