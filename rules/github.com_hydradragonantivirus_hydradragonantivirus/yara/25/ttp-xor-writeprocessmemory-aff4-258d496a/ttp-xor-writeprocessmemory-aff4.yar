rule TTP_XOR_WriteProcessMemory_aff4 {
  strings:
    $key_aff4 = { f8 86 [2] ca a4 [2] cc 91 [2] e2 91 [2] dd 8d }

  condition:
    any of them
}