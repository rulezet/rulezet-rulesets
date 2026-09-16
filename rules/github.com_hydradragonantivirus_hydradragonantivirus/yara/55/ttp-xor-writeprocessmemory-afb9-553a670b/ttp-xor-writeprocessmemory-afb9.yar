rule TTP_XOR_WriteProcessMemory_afb9 {
  strings:
    $key_afb9 = { f8 cb [2] ca e9 [2] cc dc [2] e2 dc [2] dd c0 }

  condition:
    any of them
}