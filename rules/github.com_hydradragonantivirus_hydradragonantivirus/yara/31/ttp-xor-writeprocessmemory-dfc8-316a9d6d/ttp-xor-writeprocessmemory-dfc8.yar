rule TTP_XOR_WriteProcessMemory_dfc8 {
  strings:
    $key_dfc8 = { 88 ba [2] ba 98 [2] bc ad [2] 92 ad [2] ad b1 }

  condition:
    any of them
}