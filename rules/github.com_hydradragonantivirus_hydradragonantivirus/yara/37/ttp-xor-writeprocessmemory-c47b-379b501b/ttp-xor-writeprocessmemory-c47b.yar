rule TTP_XOR_WriteProcessMemory_c47b {
  strings:
    $key_c47b = { 93 09 [2] a1 2b [2] a7 1e [2] 89 1e [2] b6 02 }

  condition:
    any of them
}