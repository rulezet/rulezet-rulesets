rule TTP_XOR_WriteProcessMemory_cef2 {
  strings:
    $key_cef2 = { 99 80 [2] ab a2 [2] ad 97 [2] 83 97 [2] bc 8b }

  condition:
    any of them
}