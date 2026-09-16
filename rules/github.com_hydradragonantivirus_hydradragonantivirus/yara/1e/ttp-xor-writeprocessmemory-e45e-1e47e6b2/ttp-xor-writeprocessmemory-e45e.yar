rule TTP_XOR_WriteProcessMemory_e45e {
  strings:
    $key_e45e = { b3 2c [2] 81 0e [2] 87 3b [2] a9 3b [2] 96 27 }

  condition:
    any of them
}