rule TTP_XOR_WriteProcessMemory_d8fe {
  strings:
    $key_d8fe = { 8f 8c [2] bd ae [2] bb 9b [2] 95 9b [2] aa 87 }

  condition:
    any of them
}