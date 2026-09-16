rule TTP_XOR_WriteProcessMemory_e54e {
  strings:
    $key_e54e = { b2 3c [2] 80 1e [2] 86 2b [2] a8 2b [2] 97 37 }

  condition:
    any of them
}