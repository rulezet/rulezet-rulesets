rule TTP_XOR_WriteProcessMemory_aa89 {
  strings:
    $key_aa89 = { fd fb [2] cf d9 [2] c9 ec [2] e7 ec [2] d8 f0 }

  condition:
    any of them
}