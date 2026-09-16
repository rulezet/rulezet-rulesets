rule TTP_XOR_WriteProcessMemory_aadb {
  strings:
    $key_aadb = { fd a9 [2] cf 8b [2] c9 be [2] e7 be [2] d8 a2 }

  condition:
    any of them
}