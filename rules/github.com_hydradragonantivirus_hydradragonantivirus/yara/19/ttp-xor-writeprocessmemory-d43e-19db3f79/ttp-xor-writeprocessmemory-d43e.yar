rule TTP_XOR_WriteProcessMemory_d43e {
  strings:
    $key_d43e = { 83 4c [2] b1 6e [2] b7 5b [2] 99 5b [2] a6 47 }

  condition:
    any of them
}