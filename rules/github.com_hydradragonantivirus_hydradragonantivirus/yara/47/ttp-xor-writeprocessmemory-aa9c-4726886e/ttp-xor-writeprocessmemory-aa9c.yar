rule TTP_XOR_WriteProcessMemory_aa9c {
  strings:
    $key_aa9c = { fd ee [2] cf cc [2] c9 f9 [2] e7 f9 [2] d8 e5 }

  condition:
    any of them
}