rule TTP_XOR_WriteProcessMemory_af28 {
  strings:
    $key_af28 = { f8 5a [2] ca 78 [2] cc 4d [2] e2 4d [2] dd 51 }

  condition:
    any of them
}