rule TTP_XOR_WriteProcessMemory_d75e {
  strings:
    $key_d75e = { 80 2c [2] b2 0e [2] b4 3b [2] 9a 3b [2] a5 27 }

  condition:
    any of them
}