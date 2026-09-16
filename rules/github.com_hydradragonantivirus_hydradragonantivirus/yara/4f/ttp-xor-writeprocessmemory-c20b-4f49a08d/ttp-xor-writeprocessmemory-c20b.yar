rule TTP_XOR_WriteProcessMemory_c20b {
  strings:
    $key_c20b = { 95 79 [2] a7 5b [2] a1 6e [2] 8f 6e [2] b0 72 }

  condition:
    any of them
}