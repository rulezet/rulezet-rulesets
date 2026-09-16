rule TTP_XOR_WriteProcessMemory_c50b {
  strings:
    $key_c50b = { 92 79 [2] a0 5b [2] a6 6e [2] 88 6e [2] b7 72 }

  condition:
    any of them
}