rule TTP_XOR_WriteProcessMemory_af1b {
  strings:
    $key_af1b = { f8 69 [2] ca 4b [2] cc 7e [2] e2 7e [2] dd 62 }

  condition:
    any of them
}