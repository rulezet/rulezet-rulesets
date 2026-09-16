rule TTP_XOR_WriteProcessMemory_afb8 {
  strings:
    $key_afb8 = { f8 ca [2] ca e8 [2] cc dd [2] e2 dd [2] dd c1 }

  condition:
    any of them
}