rule TTP_XOR_WriteProcessMemory_dfcb {
  strings:
    $key_dfcb = { 88 b9 [2] ba 9b [2] bc ae [2] 92 ae [2] ad b2 }

  condition:
    any of them
}