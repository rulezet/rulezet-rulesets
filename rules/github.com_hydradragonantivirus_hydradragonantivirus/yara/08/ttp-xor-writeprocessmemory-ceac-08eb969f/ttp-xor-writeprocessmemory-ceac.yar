rule TTP_XOR_WriteProcessMemory_ceac {
  strings:
    $key_ceac = { 99 de [2] ab fc [2] ad c9 [2] 83 c9 [2] bc d5 }

  condition:
    any of them
}