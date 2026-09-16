rule TTP_XOR_WriteProcessMemory_af42 {
  strings:
    $key_af42 = { f8 30 [2] ca 12 [2] cc 27 [2] e2 27 [2] dd 3b }

  condition:
    any of them
}