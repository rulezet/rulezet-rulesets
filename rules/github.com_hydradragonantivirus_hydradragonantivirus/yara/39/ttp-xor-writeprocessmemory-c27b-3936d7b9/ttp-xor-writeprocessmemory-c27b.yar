rule TTP_XOR_WriteProcessMemory_c27b {
  strings:
    $key_c27b = { 95 09 [2] a7 2b [2] a1 1e [2] 8f 1e [2] b0 02 }

  condition:
    any of them
}