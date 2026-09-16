rule TTP_XOR_WriteProcessMemory_d44e {
  strings:
    $key_d44e = { 83 3c [2] b1 1e [2] b7 2b [2] 99 2b [2] a6 37 }

  condition:
    any of them
}