rule TTP_XOR_WriteProcessMemory_afff {
  strings:
    $key_afff = { f8 8d [2] ca af [2] cc 9a [2] e2 9a [2] dd 86 }

  condition:
    any of them
}