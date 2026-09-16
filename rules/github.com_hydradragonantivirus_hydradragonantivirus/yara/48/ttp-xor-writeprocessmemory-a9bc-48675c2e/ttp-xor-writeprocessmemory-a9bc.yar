rule TTP_XOR_WriteProcessMemory_a9bc {
  strings:
    $key_a9bc = { fe ce [2] cc ec [2] ca d9 [2] e4 d9 [2] db c5 }

  condition:
    any of them
}