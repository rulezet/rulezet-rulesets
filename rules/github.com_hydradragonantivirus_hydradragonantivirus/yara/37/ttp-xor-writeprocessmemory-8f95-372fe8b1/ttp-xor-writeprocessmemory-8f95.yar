rule TTP_XOR_WriteProcessMemory_8f95 {
  strings:
    $key_8f95 = { d8 e7 [2] ea c5 [2] ec f0 [2] c2 f0 [2] fd ec }

  condition:
    any of them
}