rule TTP_XOR_WriteProcessMemory_d17b {
  strings:
    $key_d17b = { 86 09 [2] b4 2b [2] b2 1e [2] 9c 1e [2] a3 02 }

  condition:
    any of them
}