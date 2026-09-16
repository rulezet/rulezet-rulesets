rule TTP_XOR_WriteProcessMemory_ed4e {
  strings:
    $key_ed4e = { ba 3c [2] 88 1e [2] 8e 2b [2] a0 2b [2] 9f 37 }

  condition:
    any of them
}