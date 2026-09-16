rule TTP_XOR_WriteProcessMemory_af54 {
  strings:
    $key_af54 = { f8 26 [2] ca 04 [2] cc 31 [2] e2 31 [2] dd 2d }

  condition:
    any of them
}