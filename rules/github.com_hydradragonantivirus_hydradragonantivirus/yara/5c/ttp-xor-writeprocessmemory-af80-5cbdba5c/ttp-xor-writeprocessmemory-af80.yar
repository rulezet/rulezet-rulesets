rule TTP_XOR_WriteProcessMemory_af80 {
  strings:
    $key_af80 = { f8 f2 [2] ca d0 [2] cc e5 [2] e2 e5 [2] dd f9 }

  condition:
    any of them
}