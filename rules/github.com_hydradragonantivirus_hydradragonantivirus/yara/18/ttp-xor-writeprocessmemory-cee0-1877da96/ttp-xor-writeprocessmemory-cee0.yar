rule TTP_XOR_WriteProcessMemory_cee0 {
  strings:
    $key_cee0 = { 99 92 [2] ab b0 [2] ad 85 [2] 83 85 [2] bc 99 }

  condition:
    any of them
}