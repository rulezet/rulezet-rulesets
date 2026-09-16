rule TTP_XOR_WriteProcessMemory_af3c {
  strings:
    $key_af3c = { f8 4e [2] ca 6c [2] cc 59 [2] e2 59 [2] dd 45 }

  condition:
    any of them
}