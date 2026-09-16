rule TTP_XOR_WriteProcessMemory_cedd {
  strings:
    $key_cedd = { 99 af [2] ab 8d [2] ad b8 [2] 83 b8 [2] bc a4 }

  condition:
    any of them
}