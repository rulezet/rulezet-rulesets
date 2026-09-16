rule TTP_XOR_WriteProcessMemory_cee5 {
  strings:
    $key_cee5 = { 99 97 [2] ab b5 [2] ad 80 [2] 83 80 [2] bc 9c }

  condition:
    any of them
}