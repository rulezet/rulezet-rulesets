rule TTP_XOR_WriteProcessMemory_dffe {
  strings:
    $key_dffe = { 88 8c [2] ba ae [2] bc 9b [2] 92 9b [2] ad 87 }

  condition:
    any of them
}