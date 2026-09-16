rule TTP_XOR_WriteProcessMemory_b55e {
  strings:
    $key_b55e = { e2 2c [2] d0 0e [2] d6 3b [2] f8 3b [2] c7 27 }

  condition:
    any of them
}