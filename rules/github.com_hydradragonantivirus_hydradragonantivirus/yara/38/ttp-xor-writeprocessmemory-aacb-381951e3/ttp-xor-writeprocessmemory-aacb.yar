rule TTP_XOR_WriteProcessMemory_aacb {
  strings:
    $key_aacb = { fd b9 [2] cf 9b [2] c9 ae [2] e7 ae [2] d8 b2 }

  condition:
    any of them
}