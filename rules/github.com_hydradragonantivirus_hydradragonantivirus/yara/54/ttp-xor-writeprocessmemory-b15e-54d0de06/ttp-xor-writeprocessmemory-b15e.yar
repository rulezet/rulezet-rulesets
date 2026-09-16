rule TTP_XOR_WriteProcessMemory_b15e {
  strings:
    $key_b15e = { e6 2c [2] d4 0e [2] d2 3b [2] fc 3b [2] c3 27 }

  condition:
    any of them
}