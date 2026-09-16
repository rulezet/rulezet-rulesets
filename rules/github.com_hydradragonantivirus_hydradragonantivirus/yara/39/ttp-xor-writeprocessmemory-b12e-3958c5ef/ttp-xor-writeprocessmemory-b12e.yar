rule TTP_XOR_WriteProcessMemory_b12e {
  strings:
    $key_b12e = { e6 5c [2] d4 7e [2] d2 4b [2] fc 4b [2] c3 57 }

  condition:
    any of them
}