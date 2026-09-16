rule TTP_XOR_WriteProcessMemory_aad3 {
  strings:
    $key_aad3 = { fd a1 [2] cf 83 [2] c9 b6 [2] e7 b6 [2] d8 aa }

  condition:
    any of them
}