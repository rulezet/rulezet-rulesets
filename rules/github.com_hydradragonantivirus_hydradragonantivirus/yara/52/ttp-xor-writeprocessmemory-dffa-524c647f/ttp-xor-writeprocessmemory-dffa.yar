rule TTP_XOR_WriteProcessMemory_dffa {
  strings:
    $key_dffa = { 88 88 [2] ba aa [2] bc 9f [2] 92 9f [2] ad 83 }

  condition:
    any of them
}