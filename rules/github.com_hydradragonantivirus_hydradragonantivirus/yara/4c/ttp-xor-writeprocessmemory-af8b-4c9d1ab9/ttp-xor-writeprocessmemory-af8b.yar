rule TTP_XOR_WriteProcessMemory_af8b {
  strings:
    $key_af8b = { f8 f9 [2] ca db [2] cc ee [2] e2 ee [2] dd f2 }

  condition:
    any of them
}