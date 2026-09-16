rule TTP_XOR_WriteProcessMemory_c17b {
  strings:
    $key_c17b = { 96 09 [2] a4 2b [2] a2 1e [2] 8c 1e [2] b3 02 }

  condition:
    any of them
}