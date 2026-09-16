rule TTP_XOR_WriteProcessMemory_c22e {
  strings:
    $key_c22e = { 95 5c [2] a7 7e [2] a1 4b [2] 8f 4b [2] b0 57 }

  condition:
    any of them
}