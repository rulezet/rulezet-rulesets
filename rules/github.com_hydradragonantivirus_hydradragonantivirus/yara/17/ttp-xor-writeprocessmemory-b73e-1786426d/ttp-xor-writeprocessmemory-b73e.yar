rule TTP_XOR_WriteProcessMemory_b73e {
  strings:
    $key_b73e = { e0 4c [2] d2 6e [2] d4 5b [2] fa 5b [2] c5 47 }

  condition:
    any of them
}