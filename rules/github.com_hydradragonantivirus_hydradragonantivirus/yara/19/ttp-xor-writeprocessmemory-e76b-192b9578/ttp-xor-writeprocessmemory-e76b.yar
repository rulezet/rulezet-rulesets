rule TTP_XOR_WriteProcessMemory_e76b {
  strings:
    $key_e76b = { b0 19 [2] 82 3b [2] 84 0e [2] aa 0e [2] 95 12 }

  condition:
    any of them
}