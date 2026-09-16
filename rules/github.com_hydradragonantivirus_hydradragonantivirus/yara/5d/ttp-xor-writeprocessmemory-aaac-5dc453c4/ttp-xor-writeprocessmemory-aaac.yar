rule TTP_XOR_WriteProcessMemory_aaac {
  strings:
    $key_aaac = { fd de [2] cf fc [2] c9 c9 [2] e7 c9 [2] d8 d5 }

  condition:
    any of them
}