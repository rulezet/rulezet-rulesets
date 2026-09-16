rule TTP_XOR_WriteProcessMemory_1f9c {
  strings:
    $key_1f9c = { 48 ee [2] 7a cc [2] 7c f9 [2] 52 f9 [2] 6d e5 }

  condition:
    any of them
}