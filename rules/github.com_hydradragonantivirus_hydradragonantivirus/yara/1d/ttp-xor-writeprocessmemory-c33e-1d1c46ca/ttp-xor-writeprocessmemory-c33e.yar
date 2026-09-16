rule TTP_XOR_WriteProcessMemory_c33e {
  strings:
    $key_c33e = { 94 4c [2] a6 6e [2] a0 5b [2] 8e 5b [2] b1 47 }

  condition:
    any of them
}