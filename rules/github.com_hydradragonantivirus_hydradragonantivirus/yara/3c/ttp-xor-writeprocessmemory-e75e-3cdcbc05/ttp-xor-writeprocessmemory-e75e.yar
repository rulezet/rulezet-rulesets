rule TTP_XOR_WriteProcessMemory_e75e {
  strings:
    $key_e75e = { b0 2c [2] 82 0e [2] 84 3b [2] aa 3b [2] 95 27 }

  condition:
    any of them
}