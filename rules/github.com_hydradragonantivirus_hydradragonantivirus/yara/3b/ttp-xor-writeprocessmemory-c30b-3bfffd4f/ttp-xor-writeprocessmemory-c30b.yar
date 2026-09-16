rule TTP_XOR_WriteProcessMemory_c30b {
  strings:
    $key_c30b = { 94 79 [2] a6 5b [2] a0 6e [2] 8e 6e [2] b1 72 }

  condition:
    any of them
}