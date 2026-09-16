rule TTP_XOR_WriteProcessMemory_e44e {
  strings:
    $key_e44e = { b3 3c [2] 81 1e [2] 87 2b [2] a9 2b [2] 96 37 }

  condition:
    any of them
}