rule TTP_XOR_WriteProcessMemory_e04e {
  strings:
    $key_e04e = { b7 3c [2] 85 1e [2] 83 2b [2] ad 2b [2] 92 37 }

  condition:
    any of them
}