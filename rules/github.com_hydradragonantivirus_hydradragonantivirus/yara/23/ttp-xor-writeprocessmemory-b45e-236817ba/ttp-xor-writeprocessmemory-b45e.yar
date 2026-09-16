rule TTP_XOR_WriteProcessMemory_b45e {
  strings:
    $key_b45e = { e3 2c [2] d1 0e [2] d7 3b [2] f9 3b [2] c6 27 }

  condition:
    any of them
}