rule TTP_XOR_WriteProcessMemory_eb4e {
  strings:
    $key_eb4e = { bc 3c [2] 8e 1e [2] 88 2b [2] a6 2b [2] 99 37 }

  condition:
    any of them
}