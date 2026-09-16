rule TTP_XOR_WriteProcessMemory_aadf {
  strings:
    $key_aadf = { fd ad [2] cf 8f [2] c9 ba [2] e7 ba [2] d8 a6 }

  condition:
    any of them
}