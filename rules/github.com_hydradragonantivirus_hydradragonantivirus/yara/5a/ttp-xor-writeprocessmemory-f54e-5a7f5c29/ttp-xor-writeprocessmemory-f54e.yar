rule TTP_XOR_WriteProcessMemory_f54e {
  strings:
    $key_f54e = { a2 3c [2] 90 1e [2] 96 2b [2] b8 2b [2] 87 37 }

  condition:
    any of them
}