rule TTP_XOR_WriteProcessMemory_af69 {
  strings:
    $key_af69 = { f8 1b [2] ca 39 [2] cc 0c [2] e2 0c [2] dd 10 }

  condition:
    any of them
}