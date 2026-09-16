rule TTP_XOR_WriteProcessMemory_e43e {
  strings:
    $key_e43e = { b3 4c [2] 81 6e [2] 87 5b [2] a9 5b [2] 96 47 }

  condition:
    any of them
}