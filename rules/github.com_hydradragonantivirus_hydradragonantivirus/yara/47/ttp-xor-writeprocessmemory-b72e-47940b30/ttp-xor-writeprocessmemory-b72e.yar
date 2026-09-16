rule TTP_XOR_WriteProcessMemory_b72e {
  strings:
    $key_b72e = { e0 5c [2] d2 7e [2] d4 4b [2] fa 4b [2] c5 57 }

  condition:
    any of them
}