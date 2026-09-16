rule TTP_XOR_WriteProcessMemory_af16 {
  strings:
    $key_af16 = { f8 64 [2] ca 46 [2] cc 73 [2] e2 73 [2] dd 6f }

  condition:
    any of them
}