rule TTP_XOR_WriteProcessMemory_c43e {
  strings:
    $key_c43e = { 93 4c [2] a1 6e [2] a7 5b [2] 89 5b [2] b6 47 }

  condition:
    any of them
}