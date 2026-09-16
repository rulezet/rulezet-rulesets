rule TTP_XOR_WriteProcessMemory_d34e {
  strings:
    $key_d34e = { 84 3c [2] b6 1e [2] b0 2b [2] 9e 2b [2] a1 37 }

  condition:
    any of them
}