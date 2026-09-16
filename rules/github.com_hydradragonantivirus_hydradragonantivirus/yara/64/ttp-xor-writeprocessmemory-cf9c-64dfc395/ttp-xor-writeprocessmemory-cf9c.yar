rule TTP_XOR_WriteProcessMemory_cf9c {
  strings:
    $key_cf9c = { 98 ee [2] aa cc [2] ac f9 [2] 82 f9 [2] bd e5 }

  condition:
    any of them
}