rule TTP_XOR_WriteProcessMemory_aff9 {
  strings:
    $key_aff9 = { f8 8b [2] ca a9 [2] cc 9c [2] e2 9c [2] dd 80 }

  condition:
    any of them
}