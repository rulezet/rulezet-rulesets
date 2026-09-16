rule TTP_XOR_WriteProcessMemory_af17 {
  strings:
    $key_af17 = { f8 65 [2] ca 47 [2] cc 72 [2] e2 72 [2] dd 6e }

  condition:
    any of them
}