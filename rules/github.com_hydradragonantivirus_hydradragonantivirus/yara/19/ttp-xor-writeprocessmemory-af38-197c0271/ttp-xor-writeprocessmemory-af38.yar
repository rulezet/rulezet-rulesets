rule TTP_XOR_WriteProcessMemory_af38 {
  strings:
    $key_af38 = { f8 4a [2] ca 68 [2] cc 5d [2] e2 5d [2] dd 41 }

  condition:
    any of them
}