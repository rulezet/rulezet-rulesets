rule TTP_XOR_WriteProcessMemory_aad4 {
  strings:
    $key_aad4 = { fd a6 [2] cf 84 [2] c9 b1 [2] e7 b1 [2] d8 ad }

  condition:
    any of them
}