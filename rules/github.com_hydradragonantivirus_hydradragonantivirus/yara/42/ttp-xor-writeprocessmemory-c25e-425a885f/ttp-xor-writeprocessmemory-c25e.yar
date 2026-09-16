rule TTP_XOR_WriteProcessMemory_c25e {
  strings:
    $key_c25e = { 95 2c [2] a7 0e [2] a1 3b [2] 8f 3b [2] b0 27 }

  condition:
    any of them
}