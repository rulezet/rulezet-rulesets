rule TTP_XOR_WriteProcessMemory_7f9c {
  strings:
    $key_7f9c = { 28 ee [2] 1a cc [2] 1c f9 [2] 32 f9 [2] 0d e5 }

  condition:
    any of them
}