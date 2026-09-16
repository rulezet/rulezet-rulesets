rule TTP_XOR_WriteProcessMemory_af2c {
  strings:
    $key_af2c = { f8 5e [2] ca 7c [2] cc 49 [2] e2 49 [2] dd 55 }

  condition:
    any of them
}