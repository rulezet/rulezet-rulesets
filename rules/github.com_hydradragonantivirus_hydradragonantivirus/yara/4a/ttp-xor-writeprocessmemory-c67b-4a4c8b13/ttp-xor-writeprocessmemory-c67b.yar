rule TTP_XOR_WriteProcessMemory_c67b {
  strings:
    $key_c67b = { 91 09 [2] a3 2b [2] a5 1e [2] 8b 1e [2] b4 02 }

  condition:
    any of them
}