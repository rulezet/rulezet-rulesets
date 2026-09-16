rule TTP_XOR_WriteProcessMemory_b75e {
  strings:
    $key_b75e = { e0 2c [2] d2 0e [2] d4 3b [2] fa 3b [2] c5 27 }

  condition:
    any of them
}