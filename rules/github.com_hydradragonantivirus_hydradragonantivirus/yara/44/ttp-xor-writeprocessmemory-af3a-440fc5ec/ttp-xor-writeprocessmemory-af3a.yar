rule TTP_XOR_WriteProcessMemory_af3a {
  strings:
    $key_af3a = { f8 48 [2] ca 6a [2] cc 5f [2] e2 5f [2] dd 43 }

  condition:
    any of them
}