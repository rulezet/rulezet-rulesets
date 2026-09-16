rule TTP_XOR_WriteProcessMemory_cef4 {
  strings:
    $key_cef4 = { 99 86 [2] ab a4 [2] ad 91 [2] 83 91 [2] bc 8d }

  condition:
    any of them
}