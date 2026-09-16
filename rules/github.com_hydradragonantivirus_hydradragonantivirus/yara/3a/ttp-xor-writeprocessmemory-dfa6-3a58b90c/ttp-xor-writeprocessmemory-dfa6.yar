rule TTP_XOR_WriteProcessMemory_dfa6 {
  strings:
    $key_dfa6 = { 88 d4 [2] ba f6 [2] bc c3 [2] 92 c3 [2] ad df }

  condition:
    any of them
}