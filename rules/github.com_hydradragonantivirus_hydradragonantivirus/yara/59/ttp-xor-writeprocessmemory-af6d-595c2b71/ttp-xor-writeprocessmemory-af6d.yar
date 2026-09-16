rule TTP_XOR_WriteProcessMemory_af6d {
  strings:
    $key_af6d = { f8 1f [2] ca 3d [2] cc 08 [2] e2 08 [2] dd 14 }

  condition:
    any of them
}