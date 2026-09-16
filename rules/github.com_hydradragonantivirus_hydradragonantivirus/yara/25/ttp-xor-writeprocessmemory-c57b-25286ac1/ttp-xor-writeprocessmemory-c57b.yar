rule TTP_XOR_WriteProcessMemory_c57b {
  strings:
    $key_c57b = { 92 09 [2] a0 2b [2] a6 1e [2] 88 1e [2] b7 02 }

  condition:
    any of them
}