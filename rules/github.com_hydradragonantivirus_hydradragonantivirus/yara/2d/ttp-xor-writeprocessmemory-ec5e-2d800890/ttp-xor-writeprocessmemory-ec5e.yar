rule TTP_XOR_WriteProcessMemory_ec5e {
  strings:
    $key_ec5e = { bb 2c [2] 89 0e [2] 8f 3b [2] a1 3b [2] 9e 27 }

  condition:
    any of them
}