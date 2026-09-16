rule TTP_XOR_WriteProcessMemory_c74e {
  strings:
    $key_c74e = { 90 3c [2] a2 1e [2] a4 2b [2] 8a 2b [2] b5 37 }

  condition:
    any of them
}