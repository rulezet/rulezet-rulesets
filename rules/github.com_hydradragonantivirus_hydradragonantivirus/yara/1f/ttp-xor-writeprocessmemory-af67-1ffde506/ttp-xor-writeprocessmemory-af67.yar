rule TTP_XOR_WriteProcessMemory_af67 {
  strings:
    $key_af67 = { f8 15 [2] ca 37 [2] cc 02 [2] e2 02 [2] dd 1e }

  condition:
    any of them
}