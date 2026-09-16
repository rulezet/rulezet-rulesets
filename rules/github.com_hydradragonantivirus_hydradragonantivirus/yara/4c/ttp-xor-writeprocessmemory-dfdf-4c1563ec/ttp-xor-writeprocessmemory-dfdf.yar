rule TTP_XOR_WriteProcessMemory_dfdf {
  strings:
    $key_dfdf = { 88 ad [2] ba 8f [2] bc ba [2] 92 ba [2] ad a6 }

  condition:
    any of them
}