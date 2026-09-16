rule TTP_XOR_WriteProcessMemory_e06c {
  strings:
    $key_e06c = { b7 1e [2] 85 3c [2] 83 09 [2] ad 09 [2] 92 15 }

  condition:
    any of them
}