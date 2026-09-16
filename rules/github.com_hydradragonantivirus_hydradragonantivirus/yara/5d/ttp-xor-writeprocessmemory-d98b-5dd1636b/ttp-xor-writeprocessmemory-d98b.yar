rule TTP_XOR_WriteProcessMemory_d98b {
  strings:
    $key_d98b = { 8e f9 [2] bc db [2] ba ee [2] 94 ee [2] ab f2 }

  condition:
    any of them
}