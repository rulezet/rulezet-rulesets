rule TTP_XOR_WriteProcessMemory_d35e {
  strings:
    $key_d35e = { 84 2c [2] b6 0e [2] b0 3b [2] 9e 3b [2] a1 27 }

  condition:
    any of them
}