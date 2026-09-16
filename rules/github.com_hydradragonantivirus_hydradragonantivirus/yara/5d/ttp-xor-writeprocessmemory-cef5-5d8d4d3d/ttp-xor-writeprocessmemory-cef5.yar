rule TTP_XOR_WriteProcessMemory_cef5 {
  strings:
    $key_cef5 = { 99 87 [2] ab a5 [2] ad 90 [2] 83 90 [2] bc 8c }

  condition:
    any of them
}