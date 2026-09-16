rule TTP_XOR_WriteProcessMemory_aad0 {
  strings:
    $key_aad0 = { fd a2 [2] cf 80 [2] c9 b5 [2] e7 b5 [2] d8 a9 }

  condition:
    any of them
}