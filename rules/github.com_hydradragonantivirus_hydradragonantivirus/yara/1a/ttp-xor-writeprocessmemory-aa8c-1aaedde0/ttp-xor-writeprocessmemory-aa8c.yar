rule TTP_XOR_WriteProcessMemory_aa8c {
  strings:
    $key_aa8c = { fd fe [2] cf dc [2] c9 e9 [2] e7 e9 [2] d8 f5 }

  condition:
    any of them
}