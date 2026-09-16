rule TTP_XOR_WriteProcessMemory_af29 {
  strings:
    $key_af29 = { f8 5b [2] ca 79 [2] cc 4c [2] e2 4c [2] dd 50 }

  condition:
    any of them
}