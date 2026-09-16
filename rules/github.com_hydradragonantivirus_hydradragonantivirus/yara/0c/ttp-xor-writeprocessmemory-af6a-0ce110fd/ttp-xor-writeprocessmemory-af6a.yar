rule TTP_XOR_WriteProcessMemory_af6a {
  strings:
    $key_af6a = { f8 18 [2] ca 3a [2] cc 0f [2] e2 0f [2] dd 13 }

  condition:
    any of them
}