rule TTP_XOR_WriteProcessMemory_af6f {
  strings:
    $key_af6f = { f8 1d [2] ca 3f [2] cc 0a [2] e2 0a [2] dd 16 }

  condition:
    any of them
}