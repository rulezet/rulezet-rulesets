rule TTP_XOR_WriteProcessMemory_ceee {
  strings:
    $key_ceee = { 99 9c [2] ab be [2] ad 8b [2] 83 8b [2] bc 97 }

  condition:
    any of them
}