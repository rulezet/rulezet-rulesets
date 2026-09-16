rule TTP_XOR_WriteProcessMemory_d904 {
  strings:
    $key_d904 = { 8e 76 [2] bc 54 [2] ba 61 [2] 94 61 [2] ab 7d }

  condition:
    any of them
}