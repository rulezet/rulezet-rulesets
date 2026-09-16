rule TTP_XOR_WriteProcessMemory_d47b {
  strings:
    $key_d47b = { 83 09 [2] b1 2b [2] b7 1e [2] 99 1e [2] a6 02 }

  condition:
    any of them
}