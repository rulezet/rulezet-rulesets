rule TTP_XOR_WriteProcessMemory_afac {
  strings:
    $key_afac = { f8 de [2] ca fc [2] cc c9 [2] e2 c9 [2] dd d5 }

  condition:
    any of them
}