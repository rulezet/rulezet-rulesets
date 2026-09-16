rule TTP_XOR_WriteProcessMemory_dfa2 {
  strings:
    $key_dfa2 = { 88 d0 [2] ba f2 [2] bc c7 [2] 92 c7 [2] ad db }

  condition:
    any of them
}