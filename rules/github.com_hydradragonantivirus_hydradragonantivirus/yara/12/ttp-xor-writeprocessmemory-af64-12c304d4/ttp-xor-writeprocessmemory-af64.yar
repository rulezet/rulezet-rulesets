rule TTP_XOR_WriteProcessMemory_af64 {
  strings:
    $key_af64 = { f8 16 [2] ca 34 [2] cc 01 [2] e2 01 [2] dd 1d }

  condition:
    any of them
}