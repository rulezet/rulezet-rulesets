rule TTP_XOR_WriteProcessMemory_c76b {
  strings:
    $key_c76b = { 90 19 [2] a2 3b [2] a4 0e [2] 8a 0e [2] b5 12 }

  condition:
    any of them
}