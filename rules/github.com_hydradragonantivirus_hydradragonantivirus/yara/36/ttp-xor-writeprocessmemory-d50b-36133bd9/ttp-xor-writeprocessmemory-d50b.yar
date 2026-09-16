rule TTP_XOR_WriteProcessMemory_d50b {
  strings:
    $key_d50b = { 82 79 [2] b0 5b [2] b6 6e [2] 98 6e [2] a7 72 }

  condition:
    any of them
}