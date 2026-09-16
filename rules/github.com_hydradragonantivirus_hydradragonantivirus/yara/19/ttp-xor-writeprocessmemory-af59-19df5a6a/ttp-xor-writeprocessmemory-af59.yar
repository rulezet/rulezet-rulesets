rule TTP_XOR_WriteProcessMemory_af59 {
  strings:
    $key_af59 = { f8 2b [2] ca 09 [2] cc 3c [2] e2 3c [2] dd 20 }

  condition:
    any of them
}