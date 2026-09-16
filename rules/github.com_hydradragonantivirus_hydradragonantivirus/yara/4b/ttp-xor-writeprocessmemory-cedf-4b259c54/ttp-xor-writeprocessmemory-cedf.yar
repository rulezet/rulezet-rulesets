rule TTP_XOR_WriteProcessMemory_cedf {
  strings:
    $key_cedf = { 99 ad [2] ab 8f [2] ad ba [2] 83 ba [2] bc a6 }

  condition:
    any of them
}