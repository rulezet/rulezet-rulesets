rule TTP_XOR_WriteProcessMemory_aa9d {
  strings:
    $key_aa9d = { fd ef [2] cf cd [2] c9 f8 [2] e7 f8 [2] d8 e4 }

  condition:
    any of them
}