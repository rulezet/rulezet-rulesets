rule TTP_XOR_WriteProcessMemory_afef {
  strings:
    $key_afef = { f8 9d [2] ca bf [2] cc 8a [2] e2 8a [2] dd 96 }

  condition:
    any of them
}