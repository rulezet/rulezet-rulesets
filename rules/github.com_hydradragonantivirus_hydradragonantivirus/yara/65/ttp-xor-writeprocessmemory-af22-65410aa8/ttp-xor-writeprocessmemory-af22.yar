rule TTP_XOR_WriteProcessMemory_af22 {
  strings:
    $key_af22 = { f8 50 [2] ca 72 [2] cc 47 [2] e2 47 [2] dd 5b }

  condition:
    any of them
}