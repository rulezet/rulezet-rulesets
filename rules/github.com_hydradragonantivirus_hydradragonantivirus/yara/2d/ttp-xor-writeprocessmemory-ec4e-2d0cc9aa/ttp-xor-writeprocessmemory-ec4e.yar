rule TTP_XOR_WriteProcessMemory_ec4e {
  strings:
    $key_ec4e = { bb 3c [2] 89 1e [2] 8f 2b [2] a1 2b [2] 9e 37 }

  condition:
    any of them
}