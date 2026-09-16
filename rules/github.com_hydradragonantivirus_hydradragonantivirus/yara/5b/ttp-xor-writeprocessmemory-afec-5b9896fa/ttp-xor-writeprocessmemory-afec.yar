rule TTP_XOR_WriteProcessMemory_afec {
  strings:
    $key_afec = { f8 9e [2] ca bc [2] cc 89 [2] e2 89 [2] dd 95 }

  condition:
    any of them
}