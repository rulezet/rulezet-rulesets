rule TTP_XOR_WriteProcessMemory_c06b {
  strings:
    $key_c06b = { 97 19 [2] a5 3b [2] a3 0e [2] 8d 0e [2] b2 12 }

  condition:
    any of them
}