rule TTP_XOR_WriteProcessMemory_d9fe {
  strings:
    $key_d9fe = { 8e 8c [2] bc ae [2] ba 9b [2] 94 9b [2] ab 87 }

  condition:
    any of them
}