rule TTP_XOR_WriteProcessMemory_e07b {
  strings:
    $key_e07b = { b7 09 [2] 85 2b [2] 83 1e [2] ad 1e [2] 92 02 }

  condition:
    any of them
}