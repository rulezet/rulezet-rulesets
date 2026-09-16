rule TTP_XOR_WriteProcessMemory_d15e {
  strings:
    $key_d15e = { 86 2c [2] b4 0e [2] b2 3b [2] 9c 3b [2] a3 27 }

  condition:
    any of them
}