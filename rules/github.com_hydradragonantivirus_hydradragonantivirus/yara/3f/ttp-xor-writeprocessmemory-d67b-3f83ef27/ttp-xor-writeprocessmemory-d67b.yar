rule TTP_XOR_WriteProcessMemory_d67b {
  strings:
    $key_d67b = { 81 09 [2] b3 2b [2] b5 1e [2] 9b 1e [2] a4 02 }

  condition:
    any of them
}