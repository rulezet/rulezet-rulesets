rule TTP_XOR_WriteProcessMemory_c24e {
  strings:
    $key_c24e = { 95 3c [2] a7 1e [2] a1 2b [2] 8f 2b [2] b0 37 }

  condition:
    any of them
}