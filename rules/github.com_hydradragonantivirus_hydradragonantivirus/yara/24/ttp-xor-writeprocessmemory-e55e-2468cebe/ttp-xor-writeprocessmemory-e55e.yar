rule TTP_XOR_WriteProcessMemory_e55e {
  strings:
    $key_e55e = { b2 2c [2] 80 0e [2] 86 3b [2] a8 3b [2] 97 27 }

  condition:
    any of them
}