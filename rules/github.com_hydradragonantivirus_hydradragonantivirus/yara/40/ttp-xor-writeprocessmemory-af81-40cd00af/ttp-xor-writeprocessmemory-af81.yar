rule TTP_XOR_WriteProcessMemory_af81 {
  strings:
    $key_af81 = { f8 f3 [2] ca d1 [2] cc e4 [2] e2 e4 [2] dd f8 }

  condition:
    any of them
}