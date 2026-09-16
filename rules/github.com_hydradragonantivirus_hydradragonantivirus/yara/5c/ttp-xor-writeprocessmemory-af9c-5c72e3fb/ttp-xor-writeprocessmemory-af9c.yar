rule TTP_XOR_WriteProcessMemory_af9c {
  strings:
    $key_af9c = { f8 ee [2] ca cc [2] cc f9 [2] e2 f9 [2] dd e5 }

  condition:
    any of them
}