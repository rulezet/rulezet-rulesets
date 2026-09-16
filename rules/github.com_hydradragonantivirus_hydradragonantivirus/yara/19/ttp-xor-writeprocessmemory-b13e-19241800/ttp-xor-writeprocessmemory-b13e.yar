rule TTP_XOR_WriteProcessMemory_b13e {
  strings:
    $key_b13e = { e6 4c [2] d4 6e [2] d2 5b [2] fc 5b [2] c3 47 }

  condition:
    any of them
}