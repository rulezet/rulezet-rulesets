rule TTP_XOR_WriteProcessMemory_af3f {
  strings:
    $key_af3f = { f8 4d [2] ca 6f [2] cc 5a [2] e2 5a [2] dd 46 }

  condition:
    any of them
}