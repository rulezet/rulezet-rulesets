rule TTP_XOR_WriteProcessMemory_d13e {
  strings:
    $key_d13e = { 86 4c [2] b4 6e [2] b2 5b [2] 9c 5b [2] a3 47 }

  condition:
    any of them
}