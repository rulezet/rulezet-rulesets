rule TTP_XOR_WriteProcessMemory_cef0 {
  strings:
    $key_cef0 = { 99 82 [2] ab a0 [2] ad 95 [2] 83 95 [2] bc 89 }

  condition:
    any of them
}