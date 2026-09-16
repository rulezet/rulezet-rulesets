rule TTP_XOR_WriteProcessMemory_e27b {
  strings:
    $key_e27b = { b5 09 [2] 87 2b [2] 81 1e [2] af 1e [2] 90 02 }

  condition:
    any of them
}