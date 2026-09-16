rule TTP_XOR_WriteProcessMemory_c70b {
  strings:
    $key_c70b = { 90 79 [2] a2 5b [2] a4 6e [2] 8a 6e [2] b5 72 }

  condition:
    any of them
}