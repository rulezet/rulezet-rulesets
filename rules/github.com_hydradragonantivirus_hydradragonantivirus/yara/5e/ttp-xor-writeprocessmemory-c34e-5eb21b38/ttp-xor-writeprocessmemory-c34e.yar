rule TTP_XOR_WriteProcessMemory_c34e {
  strings:
    $key_c34e = { 94 3c [2] a6 1e [2] a0 2b [2] 8e 2b [2] b1 37 }

  condition:
    any of them
}