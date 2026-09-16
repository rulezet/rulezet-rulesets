rule TTP_XOR_WriteProcessMemory_d65e {
  strings:
    $key_d65e = { 81 2c [2] b3 0e [2] b5 3b [2] 9b 3b [2] a4 27 }

  condition:
    any of them
}