rule TTP_XOR_WriteProcessMemory_af48 {
  strings:
    $key_af48 = { f8 3a [2] ca 18 [2] cc 2d [2] e2 2d [2] dd 31 }

  condition:
    any of them
}