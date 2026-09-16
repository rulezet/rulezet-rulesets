rule TTP_XOR_WriteProcessMemory_c04e {
  strings:
    $key_c04e = { 97 3c [2] a5 1e [2] a3 2b [2] 8d 2b [2] b2 37 }

  condition:
    any of them
}