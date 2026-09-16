rule TTP_XOR_WriteProcessMemory_af33 {
  strings:
    $key_af33 = { f8 41 [2] ca 63 [2] cc 56 [2] e2 56 [2] dd 4a }

  condition:
    any of them
}