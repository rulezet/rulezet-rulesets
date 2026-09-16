rule TTP_XOR_WriteProcessMemory_8fac {
  strings:
    $key_8fac = { d8 de [2] ea fc [2] ec c9 [2] c2 c9 [2] fd d5 }

  condition:
    any of them
}