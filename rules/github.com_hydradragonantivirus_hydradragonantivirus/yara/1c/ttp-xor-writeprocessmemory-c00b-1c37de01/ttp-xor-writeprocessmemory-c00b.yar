rule TTP_XOR_WriteProcessMemory_c00b {
  strings:
    $key_c00b = { 97 79 [2] a5 5b [2] a3 6e [2] 8d 6e [2] b2 72 }

  condition:
    any of them
}