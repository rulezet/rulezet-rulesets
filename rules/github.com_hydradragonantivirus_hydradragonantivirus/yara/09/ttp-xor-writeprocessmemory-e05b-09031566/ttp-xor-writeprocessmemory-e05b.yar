rule TTP_XOR_WriteProcessMemory_e05b {
  strings:
    $key_e05b = { b7 29 [2] 85 0b [2] 83 3e [2] ad 3e [2] 92 22 }

  condition:
    any of them
}