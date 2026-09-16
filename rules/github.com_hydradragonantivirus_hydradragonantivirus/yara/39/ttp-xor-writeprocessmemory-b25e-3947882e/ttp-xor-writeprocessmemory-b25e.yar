rule TTP_XOR_WriteProcessMemory_b25e {
  strings:
    $key_b25e = { e5 2c [2] d7 0e [2] d1 3b [2] ff 3b [2] c0 27 }

  condition:
    any of them
}