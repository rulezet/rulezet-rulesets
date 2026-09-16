rule TTP_XOR_WriteProcessMemory_affd {
  strings:
    $key_affd = { f8 8f [2] ca ad [2] cc 98 [2] e2 98 [2] dd 84 }

  condition:
    any of them
}