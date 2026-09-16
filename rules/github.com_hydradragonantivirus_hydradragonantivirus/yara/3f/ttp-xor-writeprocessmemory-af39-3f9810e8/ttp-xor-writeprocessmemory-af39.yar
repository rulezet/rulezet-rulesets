rule TTP_XOR_WriteProcessMemory_af39 {
  strings:
    $key_af39 = { f8 4b [2] ca 69 [2] cc 5c [2] e2 5c [2] dd 40 }

  condition:
    any of them
}