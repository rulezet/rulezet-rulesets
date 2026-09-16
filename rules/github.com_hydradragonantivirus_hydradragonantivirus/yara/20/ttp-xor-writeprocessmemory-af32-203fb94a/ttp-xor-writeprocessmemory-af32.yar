rule TTP_XOR_WriteProcessMemory_af32 {
  strings:
    $key_af32 = { f8 40 [2] ca 62 [2] cc 57 [2] e2 57 [2] dd 4b }

  condition:
    any of them
}