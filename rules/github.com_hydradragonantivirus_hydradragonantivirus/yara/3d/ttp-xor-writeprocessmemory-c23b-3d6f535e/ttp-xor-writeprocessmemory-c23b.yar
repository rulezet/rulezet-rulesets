rule TTP_XOR_WriteProcessMemory_c23b {
  strings:
    $key_c23b = { 95 49 [2] a7 6b [2] a1 5e [2] 8f 5e [2] b0 42 }

  condition:
    any of them
}