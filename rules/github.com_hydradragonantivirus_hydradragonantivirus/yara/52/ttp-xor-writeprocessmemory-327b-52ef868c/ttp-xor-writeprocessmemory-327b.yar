rule TTP_XOR_WriteProcessMemory_327b {
  strings:
    $key_327b = { 65 09 [2] 57 2b [2] 51 1e [2] 7f 1e [2] 40 02 }

  condition:
    any of them
}