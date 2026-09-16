rule TTP_XOR_WriteProcessMemory_af7a {
  strings:
    $key_af7a = { f8 08 [2] ca 2a [2] cc 1f [2] e2 1f [2] dd 03 }

  condition:
    any of them
}