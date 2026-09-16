rule TTP_XOR_WriteProcessMemory_cee6 {
  strings:
    $key_cee6 = { 99 94 [2] ab b6 [2] ad 83 [2] 83 83 [2] bc 9f }

  condition:
    any of them
}