rule TTP_XOR_WriteProcessMemory_cee7 {
  strings:
    $key_cee7 = { 99 95 [2] ab b7 [2] ad 82 [2] 83 82 [2] bc 9e }

  condition:
    any of them
}