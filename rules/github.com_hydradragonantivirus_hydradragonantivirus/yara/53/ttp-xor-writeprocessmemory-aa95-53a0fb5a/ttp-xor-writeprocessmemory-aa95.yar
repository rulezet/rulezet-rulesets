rule TTP_XOR_WriteProcessMemory_aa95 {
  strings:
    $key_aa95 = { fd e7 [2] cf c5 [2] c9 f0 [2] e7 f0 [2] d8 ec }

  condition:
    any of them
}