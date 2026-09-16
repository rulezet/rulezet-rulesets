rule TTP_XOR_WriteProcessMemory_e77b {
  strings:
    $key_e77b = { b0 09 [2] 82 2b [2] 84 1e [2] aa 1e [2] 95 02 }

  condition:
    any of them
}