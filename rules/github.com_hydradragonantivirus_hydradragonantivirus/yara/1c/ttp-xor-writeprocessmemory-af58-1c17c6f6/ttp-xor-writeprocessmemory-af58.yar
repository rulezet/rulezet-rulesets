rule TTP_XOR_WriteProcessMemory_af58 {
  strings:
    $key_af58 = { f8 2a [2] ca 08 [2] cc 3d [2] e2 3d [2] dd 21 }

  condition:
    any of them
}