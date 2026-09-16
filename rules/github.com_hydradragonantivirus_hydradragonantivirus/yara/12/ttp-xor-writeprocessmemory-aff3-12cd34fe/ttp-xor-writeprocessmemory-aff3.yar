rule TTP_XOR_WriteProcessMemory_aff3 {
  strings:
    $key_aff3 = { f8 81 [2] ca a3 [2] cc 96 [2] e2 96 [2] dd 8a }

  condition:
    any of them
}